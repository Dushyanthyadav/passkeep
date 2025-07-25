
use std::f32::consts::E;
use std::{string, vec};
use std::{hash::Hash, sync::Arc};
use std::fs::File;
use std::io::{stdin, Read, Result, Write};
use std::io;
use base64;
use clap;
// use argon2::password_hash::SaltString;
// use base64ct::{Base64, Encoding};
mod kdf;
use argon2::password_hash::{self, SaltString};
use argon2::Argon2;
use kdf::argon2_encode;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng}, aes::{cipher, Aes256}, Aes256Gcm, Key, Nonce // Or `Aes128Gcm`
};
use hex::encode;
mod enc_dec;
use enc_dec::{encrypt};
use serde_json::de;
use serde_json::map::Entry;

use crate::enc_dec::{decrypt, EncryptedData};
use crate::file_man::{decrypt_data, encrypt_data, AccountDetails};
mod file_man;
//use file_man::initialize;
use std::path::Path;
use std::path::PathBuf;
use std::ffi::OsStr;
use dirs;
use std::fs;
mod cli;
use cli::prompt;
//use std::path::Path;
use rpassword;


fn main() { 
    
    let config = dirs::config_local_dir().unwrap().join("passkeep");
    let file_path = config.join("enc.bin");
    
    match config.exists() {
        true => {},
        false => {
            match fs::create_dir_all(&config) {
                Ok(_) => println!("Directory created at {}", &config.display()),
                Err(e) => panic!("failded to create directory: {}", e),
            }
        }
    }
    let args = cli::parse();
    
    let mut password = rpassword::prompt_password("Enter your master password: ").unwrap();

    match file_path.exists() {
        true => {},
        false => {
            let data = "{}".to_string();
            encrypt_data(file_path.as_path(), &password, data);
        }
    }


    let mut file_hash_map = decrypt_data(&file_path.as_path(), &password);

    if args.get_flag("Remove-All"){
        
        file_hash_map.clear();
        let file_hash_map = "{}".to_string();
        encrypt_data(&file_path.as_path(), &password, file_hash_map);


    } else if args.get_flag("Show-All") {
        
        for (account, details) in &file_hash_map {
            println!("{}", account);
            println!("Username: {}", details.user_name);
            println!("Email: {}", details.email);
            println!("password: {}", details.password);
            println!("comments: {}", details.comments);
            println!("\n --------------------------------------------------------------------- \n");
            
        }

    } else if args.get_flag("Remove") {

        let account = prompt("Account: ");
        file_hash_map.remove(&account).unwrap();

    } else if args.get_flag("Show") {

        let account = prompt("Account: ");
        if let Some(entry) = file_hash_map.get(account.as_str()){
            println!("Username: {}", entry.user_name);
            println!("Email: {}", entry.email);
            println!("password: {}", entry.password);
            println!("comments: {}", entry.comments);
        }
    
    } else if args.get_flag("Add") {

        let account = prompt("Account: ");
        let username = prompt("UserName: ");
        let email = prompt("Email: ");
        let password = prompt("Password: ");
        let comments= prompt("comments: ");

        let details = AccountDetails {
            user_name: username,
            email, 
            password, 
            comments,
        };

        
        file_hash_map.insert(account, details);

    } else if args.get_flag("Change-MasterPassword") {
        loop {
            let password1 = rpassword::prompt_password("Enter new master password: ").unwrap();
            let password2 = rpassword::prompt_password("comfirm new master password: ").unwrap();

            if password1 == password2 {
                password.clear();
                password.push_str(password1.as_str());
                break;
            }
            println!("Passwords do not match!!!!");
        }


    }


    let file_data = serde_json::to_string(&file_hash_map).unwrap();

    encrypt_data(file_path.as_path(), &password, file_data);

}