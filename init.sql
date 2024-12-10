CREATE DATABASE IF NOT EXISTS php_docker;
USE php_docker;
CREATE table IF NOT EXISTS user_keys(
    id int(1) PRIMARY KEY,
    password varchar(64) NULL,
    salt varchar(5) DEFAULT NULL,
    offset int(3) DEFAULT NULL
    );