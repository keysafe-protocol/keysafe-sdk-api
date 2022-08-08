extern crate openssl;
#[macro_use]
use std::str;
use std::cmp::*;
use std::time::SystemTime;
use serde_derive::{Deserialize, Serialize};
use actix_web::{get, post, web, Error, HttpRequest, HttpResponse, Responder, FromRequest, http::header::HeaderValue};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use hex;
use log::{error, info, warn};
extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use mysql::*;
use crate::ecall;
use crate::persistence;
use crate::endpoint::auth_token;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use rand::{thread_rng, Rng};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};


pub struct AppState {
    pub enclave: SgxEnclave,
    pub db_pool: Pool,
    pub conf: HashMap<String, String>
}

pub struct UserState {
    pub state: Arc<Mutex<HashMap<String, String>>>
}

/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // acount name
    exp: usize, // when to expire
}

struct AuthAccount {
    name: String,
}


#[derive(Deserialize)]
pub struct BaseReq {
    account: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BaseResp {
    status: String,
}

#[derive(Deserialize)]
pub struct ExchangeKeyReq {
    key: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExchangeKeyResp {
    status: String,
    key: Vec<c_char>
}

fn gen_random() -> i32 {
    let mut rng = thread_rng();
    rng.gen_range(1000..9999)
}

static SUCC: &'static str = "success";
static FAIL: &'static str = "fail";

#[post("/ks/exchange_key")]
pub async fn exchange_key(
    ex_key_req: web::Json<ExchangeKeyReq>,
    endex: web::Data<AppState>
) ->  impl Responder {
    let e = &endex.enclave;
    let mut sgx_result = sgx_status_t::SGX_SUCCESS;
    let mut out_key: Vec<u8> = vec![0; 256];
    let mut plaintext2 = vec![0; 256];
    println!("user pub key is {}", ex_key_req.key);
    let result = unsafe {
        ecall::ec_ks_exchange(e.geteid(), 
            &mut sgx_result, 
            ex_key_req.key.as_ptr() as *const c_char,
            out_key.as_mut_slice().as_mut_ptr() as * mut c_char,
            plaintext2.as_mut_slice().as_mut_ptr() as * mut c_char,
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => { 
            out_key.resize(256, 0);
            let mut chars: Vec<char>= Vec::new();
            for i in out_key {
                if i != 0 {
                    chars.push(i as char);
                }
            }
            let hex_key: String = chars.into_iter().collect();
            println!("sgx pub key {}", hex_key);
            HttpResponse::Ok().body(hex_key)
        },
        _ => panic!("exchang key failed.")
    }
}

#[derive(Deserialize)]
pub struct AuthReq {
    account: String,
    key: String,
}
// with BaseResp


#[post("/ks/auth")]
pub async fn auth(
    auth_req: web::Json<AuthReq>,
    endex: web::Data<AppState>
) -> HttpResponse {
    let e = &endex.enclave;
    let mut code :u32 = 0; // get confirm code from tee
    let result = unsafe {
        ecall::ec_auth(e.geteid(),
            &mut code,
            auth_req.account.as_ptr() as *const c_char,
            auth_req.key.as_ptr() as *const c_char
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS =>  {
            sendmail(&auth_req.account, &code.to_string(), &endex.conf);
            HttpResponse::Ok().json(BaseResp{status: SUCC.to_string()})
        },
        _ => HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
    }
}

#[derive(Deserialize)]
pub struct ConfirmReq {
    account: String,
    mail: String,
    cipher_code: String
}
// with BaseResp

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfirmResp {
    status: String,
    token: String
}

#[post("/ks/auth_confirm")]
pub async fn auth_confirm(
    confirm_req: web::Json<ConfirmReq>,
    endex: web::Data<AppState>
) -> HttpResponse {
    let e = &endex.enclave;
    let mut retval = sgx_status_t::SGX_SUCCESS;
    // cipher text to bytes
    let code = hex::decode(&confirm_req.cipher_code).expect("Decode Failed.");
    let result = unsafe {
        ecall::ec_auth_confirm(
            e.geteid(),
            &mut retval,
            confirm_req.account.as_ptr() as *const c_char,
            code.as_ptr() as *const c_char,
            u32::try_from(code.len()).unwrap(),
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS =>  {
            HttpResponse::Ok().json(
                ConfirmResp {
                    status: SUCC.to_string(),
                    token: encode(
                        &Header::default(), 
                        &Claims {
                            sub: confirm_req.account.clone(),
                            exp: (system_time() + 7 * 24 * 3600).try_into().unwrap()
                        },
                        &EncodingKey::from_secret(&endex.conf["secret"].as_bytes()),
                ).unwrap()
            })
        },
        _ => HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoResp {
    status: String,
    tee: String
}

#[get("/ks/info")]
pub async fn info(
    req: HttpRequest,
    endex: web::Data<AppState>,
) -> HttpResponse {
    let claims = auth_token::extract_token(
        req.headers().get("Authorization"),
        &endex.conf["secret"].as_str()
    );
    let claims2 = claims.unwrap();
    let account = claims2.sub.to_string();
    println!("account is {}", account);
    let stmt = format!(
        "select * from user_tee where user_id = '{}'", 
        account
    );
    // mocking tee for dev purpose
    let tee = persistence::query_user_tee(&endex.db_pool, stmt);
    if tee.is_empty() {
        return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()});
    }
    HttpResponse::Ok().json(InfoResp{
        status: SUCC.to_string(),
        tee: tee[0].tee_content.clone()
    })
}

fn calc_tee_size(e: sgx_enclave_id_t, hex_str: &String) -> usize {
    let mut size: u32 = 0;
    let bcode = hex::decode(&hex_str).expect("Decode Failed.");
    let result = unsafe {
        ecall::ec_calc_sealed_size(
            e,
            &mut size,
            u32::try_from(bcode.len()).unwrap()
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS =>  {
            size.try_into().unwrap()
        },
        _ => 0
    }
}

#[derive(Deserialize)]
pub struct SealReq {
    chain: String,
    chain_addr: String,
    cipher_secret: String
}

#[post("/ks/seal")]
pub async fn seal(
    seal_req: web::Json<SealReq>,
    req: HttpRequest,
    endex: web::Data<AppState>,
) -> HttpResponse {
    let claims = auth_token::extract_token(
        req.headers().get("Authorization"),
        &endex.conf["secret"].as_str()
    );
    let claims2 = claims.unwrap();
    let account = claims2.sub.to_string();
    println!("account is {}", account);

    let e = &endex.enclave;
    let sealed_size = calc_tee_size(e.geteid(), &seal_req.cipher_secret);
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut sealed = vec![0; usize::try_from(sealed_size).unwrap()];
    let cipher_secret = hex::decode(&seal_req.cipher_secret).expect("Decode Failed.");
    println!("sealing encrypted: {:?}", seal_req.cipher_secret);
    println!("sealing encrypted length: {}", sealed_size);

    let result = unsafe {
        ecall::ec_ks_seal(e.geteid(), &mut retval,
            account.as_ptr() as *const c_char,
            cipher_secret.as_ptr() as *const c_char, 
            u32::try_from(cipher_secret.len()).unwrap(),
            sealed.as_mut_slice().as_mut_ptr() as * mut c_void,
            sealed_size.try_into().unwrap()
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            sealed.resize(usize::try_from(sealed_size).unwrap(), 0);
            let e = hex::encode(&sealed[0..sealed_size.try_into().unwrap()]);
            persistence::insert_user_tee(
                &endex.db_pool,
                persistence::UserTee {
                    user_id: account.clone(),
                    chain: seal_req.chain.clone(),
                    chain_addr: seal_req.chain_addr.clone(),
                    tee_content: e.clone()
                }
            );
        },
        _ => println!("sgx sealing failed")
    }
    persistence::insert_user_tee(
        &endex.db_pool,
        persistence::UserTee {
            user_id: account.clone(),
            chain: seal_req.chain.clone(),
            chain_addr: seal_req.chain_addr.clone(),
            tee_content: seal_req.cipher_secret.clone()
        }
    );
    HttpResponse::Ok().json(BaseResp{status: SUCC.to_string()})
}

#[derive(Deserialize)]
pub struct UnsealReq {
    account: String,
    cond_type: String,
    chain: String,
    chain_addr: String,
    cipher_cond_value: String,
    owner: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnsealResp {
    status: String,
    cipher_secret: String
}

#[post("/ks/unseal")]
pub async fn unseal(
    unseal_req: web::Json<UnsealReq>,
    endex: web::Data<AppState>,
    req: HttpRequest,
    user_state: web::Data<UserState>
) -> HttpResponse {
    let e = &endex.enclave;
    let conf = &endex.conf;
    let systime = system_time();
    // get condition value from db sealed
    let claims = auth_token::extract_token(
        req.headers().get("Authorization"),
        &endex.conf["secret"].as_str()
    );
    let claims2 = claims.unwrap();
    let account = claims2.sub.to_string();
    println!("account is {}", account);

    let stmt = format!(
        "select * from user_tee where user_id = '{}' and chain = '{}' and chain_addr = '{}'", 
        account, unseal_req.chain.clone(), unseal_req.chain_addr.clone()
    );
    let tee = persistence::query_user_tee(&endex.db_pool, stmt);
    if tee.is_empty() {
        return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()});
    }
    let cipher_secret = tee[0].tee_content.clone();
    return HttpResponse::Ok().json(UnsealResp{
        status: SUCC.to_string(),
        cipher_secret: cipher_secret
    })

    // mock for dev purpose
    // get condition
    // let cond_stmt = format!(
    //     "select * from user_cond where kid='{}' and cond_type='{}'",
    //     unseal_req.account, unseal_req.cond_type
    // );
    // let uconds = persistence::query_user_cond(
    //     &endex.db_pool, cond_stmt 
    // );
    // if uconds.is_empty() {
    //     println!("not found any user {} cond {}.", &unseal_req.account, &unseal_req.cond_type);
    //     return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()});
    // }
    // // verify condition, if fail, return 
    // let cond_value = uconds[0].tee_cond_value.clone();

    // if &unseal_req.cond_type == "email" {
    //     let mut states = user_state.state.lock().unwrap();
    //     if let Some(v) = states.get(&unseal_req.account) {
    //         if v != &unseal_req.cipher_cond_value {
    //             println!("cipher code does not match");
    //             return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
    //         }
    //     } else {
    //         println!("state does not contain user account");
    //         return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
    //     }
    // } else if &unseal_req.cond_type == "password" {
    //     if unseal_req.cipher_cond_value != cond_value {
    //         return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
    //     }
    // } else if &unseal_req.cond_type == "gauth" {
    //     //let sealed_gauth = hex::decode(cond_value).expect("Decode failed.");
    //     let mut sgx_result = sgx_status_t::SGX_SUCCESS;
    //     println!("gauth {} with code {}", cond_value, unseal_req.cipher_cond_value.parse::<i32>().unwrap());
    //     let result = unsafe {
    //         ecall::ec_verify_gauth_code(
    //             e.geteid(),
    //             &mut sgx_result,
    //             unseal_req.cipher_cond_value.parse::<i32>().unwrap(),
    //             cond_value.as_ptr() as * const c_char,
    //             systime
    //         )
    //     };
    //     println!("sgx result return {}", result);
    //     println!("sgx result in arg {}", sgx_result);
    //     match sgx_result {
    //         sgx_status_t::SGX_SUCCESS => {},
    //         _ => return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
    //     }
    // } else if &unseal_req.cond_type == "oauth@github" {
    //     let client_id = conf.get("github_client_id").unwrap();
    //     let client_secret = conf.get("github_client_secret").unwrap();
    //     let oauth_result = github_oauth(
    //         client_id.clone(), client_secret.clone(), unseal_req.cipher_cond_value.clone());
    //     let email = parse_oauth_profile(oauth_result.clone());
    //     if email != cond_value {
    //         println!("email {}", email);
    //         println!("cond value {}", cond_value);
    //         return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()})
    //     }
    // }
    // // return sealed secret when pass verify
    // let secret_stmt = format!(
    //     "select * from user_secret where kid='{}' and chain='{}' and chain_addr='{}' and cond_type='{}'",
    //     unseal_req.owner, unseal_req.chain, unseal_req.chain_addr, unseal_req.cond_type
    // );
    // let usecrets = persistence::query_user_secret(
    //     &endex.db_pool, secret_stmt);
    // if usecrets.is_empty() {
    //     return HttpResponse::Ok().json(BaseResp{status: FAIL.to_string()});
    // }
    // let secret_value = usecrets[0].tee_secret.clone();
    // HttpResponse::Ok().json(UnsealResp{
    //     status: SUCC.to_string(),
    //     cipher_secret: secret_value
    // })
}  

fn sendmail(account: &str, msg: &str, conf: &HashMap<String, String>) -> i32 {
    if conf.get("env").unwrap() == "dev" {
        println!("send mail {} to {}", msg, account);
        return 0;
    }
    if conf.contains_key("proxy_mail") {
        return proxy_mail(account, msg, conf);
    }
    println!("send mail {} to {}", msg, account);
    let email = Message::builder()
        .from("Verification Node <verify@keysafe.network>".parse().unwrap())
        .reply_to("None <none@keysafe.network>".parse().unwrap())
        .to(format!("KS User<{}>", account).parse().unwrap())
        .subject("Confirmation Code")
        .body(String::from(msg))
        .unwrap();
    let email_account = conf.get("email_account").unwrap();
    let email_password = conf.get("email_password").unwrap();
    let email_server = conf.get("email_server").unwrap();
    let creds = Credentials::new(email_account.to_owned(), email_password.to_owned());
    let mailer = SmtpTransport::relay(email_server)
        .unwrap()
        .credentials(creds)
        .build();

    // Send the email
    match mailer.send(&email) {
        Ok(_) => { println!("Email sent successfully!"); return 0 },
        Err(e) => { println!("Could not send email: {:?}", e); return 1 },
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ProxyMailReq {
    account: String,
    msg: String
}

#[derive(Serialize, Deserialize, Debug)]
struct ProxyMailResp {
    status: String
}

fn proxy_mail(account: &str, msg: &str, conf: &HashMap<String, String>) -> i32 {
    println!("calling proxy mail {} {}", account, msg);
    let proxy_mail_server = conf.get("proxy_mail_server").unwrap();
    let client =  reqwest::blocking::Client::new();
    let proxy_mail_req = ProxyMailReq {
        account: account.to_owned(),
        msg: msg.to_owned()
    };
    let res = client.post(proxy_mail_server)
        .json(&proxy_mail_req)
        .send().unwrap().json::<ProxyMailResp>().unwrap();
    if res.status == SUCC {
        return 0;
    }
    return 1;
}

fn system_time() -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}


#[get("/health")]
pub async fn hello(endex: web::Data<AppState>) -> impl Responder {
    // for health check
    HttpResponse::Ok().body("Webapp is up and running!")
}

