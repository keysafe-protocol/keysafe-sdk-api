drop table if exists user_tee;
create table user_tee (
    user_id varchar(40) not null,
    chain varchar(40),
    chain_addr varchar(100),
    tee_content varbinary(8192),
    INDEX ks_id using hash(ks_id),
    INDEX ks_addr using hash(chain_addr),
    PRIMARY KEY(ks_id, chain, chain_addr)
)
ROW_FORMAT=COMPRESSED
CHARACTER set = utf8mb4;

