use crate::enc_dec;
use crate::kdf;
use aes_gcm::aead::OsRng;
use argon2::Algorithm;
use argon2::Version;
use argon2::password_hash::SaltString;
use rand::RngCore;
use serde_json;
use std::collections::HashMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use std::path::Path;

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct AccountDetails {
    pub user_name: String,
    pub email: String,
    pub password: String,
    pub comments: String,
}

pub struct EncFileData {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

// Here the data is json data converded to
// This function work is just to open the file and add the data that all encryption is done different fn function
fn add_data_to_file(file_path: &Path, salt: Vec<u8>, nonce: Vec<u8>, data: Vec<u8>) {
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
pub fn encrypt_data(file_path: &Path, password: &String, data: String) {
    let mut byte_salt = [0u8; 16];
    let salt = SaltString::generate(&mut OsRng)
        .as_salt()
        .decode_b64(&mut byte_salt)
        .unwrap()
        .to_vec();
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);

    let m_cost = 65536;
    let t_cost = 3;
    let p_cost = 2;
    let algorithm = Algorithm::Argon2id;
    let output_len = 32;
    let version = Version::V0x13;

    let key = kdf::argon2_encode(
        m_cost, t_cost, p_cost, output_len, version, algorithm, password, &salt,
    );

    let encypted_data = enc_dec::encrypt(
        key.as_slice().try_into().unwrap(),
        &nonce,
        &data.as_bytes().to_vec(),
    );

    add_data_to_file(
        file_path,
        salt,
        encypted_data.nonce.to_vec(),
        encypted_data.cyphertext,
    );
}

fn extract_data_from_file(file_path: &Path) -> EncFileData {
    let mut file = File::open(file_path).unwrap();

    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    file.read_exact(&mut salt).unwrap();
    file.read_exact(&mut nonce).unwrap();

    let mut ciphertext = Vec::new();

    file.read_to_end(&mut ciphertext).unwrap();
    let salt = salt.to_vec();
    let nonce = nonce.to_vec();

    EncFileData {
        salt,
        nonce,
        ciphertext,
    }
}

pub fn decrypt_data(file_path: &Path, password: &String) -> HashMap<String, AccountDetails> {
    let data = extract_data_from_file(file_path);

    let salt = data.salt;
    let nonce = data.nonce;
    let ciphertext = data.ciphertext;

    let m_cost = 65536;
    let t_cost = 3;
    let p_cost = 2;
    let algorithm = Algorithm::Argon2id;
    let output_len = 32;
    let version = Version::V0x13;

    let key = kdf::argon2_encode(
        m_cost, t_cost, p_cost, output_len, version, algorithm, password, &salt,
    );

    let decryted_data = enc_dec::decrypt(
        key.as_slice().try_into().unwrap(),
        nonce.as_slice().try_into().unwrap(),
        &ciphertext,
    );

    let result = String::from_utf8(decryted_data.decryptedtext.into_bytes()).unwrap();

    let data: HashMap<String, AccountDetails> = serde_json::from_str(&result).unwrap();

    data
}
