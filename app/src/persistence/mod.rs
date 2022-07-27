use mysql::*;
use mysql::prelude::*;

use std::fs::File;
use std::fs;

use glob::glob;
use std::io::Write;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

pub struct UserTee {
    pub user_id: String,
    pub chain: String,
    pub chain_addr: String,
    pub tee_content: String
}

pub fn insert_user_tee(pool: &Pool, utee: UserTee) {
    let mut conn = pool.get_conn().unwrap();
    let mut tx = conn.start_transaction(TxOpts::default()).unwrap();
    tx.exec_drop("delete from user_tee where user_id = ?",
        (utee.user_id.clone())).unwrap();
    tx.exec_drop("insert into user_tee (user_id, chain, chain_addr, tee_content) values (?, ?, ?, ?)",
        (utee.user_id, utee.chain, utee.chain_addr, utee.tee_content)).unwrap();
    tx.commit().unwrap();
}

pub fn query_user_tee(pool: &Pool, stmt: String) -> Vec<UserOAuth>{
    let mut conn = pool.get_conn().unwrap();
    let mut result: Vec<UserOAuth> = Vec::new();
    conn.query_iter(stmt).unwrap().for_each(|row| {
        let r:(std::string::String, std::string::String, 
            std::string::String, std::string::String) = from_row(row.unwrap());
        result.push(UserTee {
            user_id: r.0,
            chain: r.1,
            chain_addr: r.2,
            tee_content: r.3
        });
    });
    result
}
