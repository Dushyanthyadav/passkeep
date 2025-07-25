use std::collections::hash_map;
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use crate::enc_dec;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::Nonce;
use argon2::Algorithm;
use argon2::Version;
use argon2::password_hash::SaltString;
use aes_gcm::aead::OsRng;
use dirs;
use serde_json;
use std::path::Path;
use crate::kdf;

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct AccountDetails {
    pub user_name: String,
    pub email: String,
    pub password: String,
    pub comments: String
} 

//use std::path::PathBuf;

pub struct enc_file_data {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>
}

pub fn create_enc_file_empty(file_name: PathBuf) {

        let file_path = dirs::config_dir().unwrap().join("passkeep").join(&file_name);

        match file_name.exists() {
            true => {},
            false => {
                match File::create(&file_name) {
                    Ok(_) => println!("{} Created successfully", file_name.display()),
                    Err(error) => println!("{}", error)
                } 

            }

        }

    
}

// Here the data is json data converded to 
// This function work is just to open the file and add the data that all encryption is done different fn function
fn add_data_to_file(file_path: &Path, salt: Vec<u8>, nonce: Vec<u8>,  data: Vec<u8>, ) {

    let mut entire_data: Vec<u8> = Vec::new();
    entire_data.extend(salt);
    entire_data.extend(nonce);
    entire_data.extend(data);

    let mut file = OpenOptions::new()
                                .write(true)
                                .create(true)
                                .truncate(true)
                                .open(file_path)
                                .unwrap();
    file.write_all(&entire_data).unwrap();


}

// This function is use to encypt and add data to file
pub fn encrypt_data(file_path: &Path, password: &String, data: String){
    let mut byte_salt = [0u8; 16];
    let salt = SaltString::generate(&mut OsRng).as_salt().decode_b64(&mut byte_salt).unwrap().to_vec();
    //let byte_salt = byte_salt.to_vec();
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let m_cost = 65536;
    let t_cost = 3;
    let p_cost = 2;
    let algorithm = Algorithm::Argon2id;
    let output_len = 32;
    let version = Version::V0x13;

    let key = kdf::argon2_encode(m_cost, t_cost, p_cost, output_len, version, algorithm, password, &salt);
    
    let encypted_data = enc_dec::encrypt(key.as_slice().try_into().unwrap(), &nonce, &data.as_bytes().to_vec());

    add_data_to_file(file_path, salt, nonce.to_vec(), encypted_data.cyphertext);

}

 fn extract_data_from_file(file_path: &Path) -> enc_file_data {

    let mut file = File::open(file_path).unwrap();

    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    file.read_exact(&mut salt).unwrap();
    file.read_exact(&mut nonce).unwrap();

    let mut ciphertext = Vec::new();

    file.read_to_end(&mut ciphertext).unwrap();
    let salt = salt.to_vec();
    let nonce = nonce.to_vec();

    enc_file_data {salt, nonce, ciphertext}

}

pub fn decrypt_data(file_path: &Path, password: &String) -> HashMap<String, AccountDetails>{


    let mut data = extract_data_from_file(file_path);

    let salt = data.salt;
    let nonce = data.nonce;
    let mut ciphertext = data.ciphertext;

    let m_cost = 65536;
    let t_cost = 3;
    let p_cost = 2;
    let algorithm = Algorithm::Argon2id;
    let output_len = 32;
    let version = Version::V0x13;

    //println!("{:?}", &salt);

    let key = kdf::argon2_encode(m_cost, t_cost, p_cost, output_len, version, algorithm, password, &salt);

    let mut decryted_data = enc_dec::decrypt(key.as_slice().try_into().unwrap(), nonce.as_slice().try_into().unwrap(), &ciphertext);

    let result = String::from_utf8(decryted_data.decryptedtext.into_bytes()).unwrap();

    let mut data: HashMap<String, AccountDetails> = serde_json::from_str(&result).unwrap();

    data
}