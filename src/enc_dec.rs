use aes_gcm::{aead::{generic_array::GenericArray, Aead, KeyInit}, aes::{cipher}, Aes256Gcm, Key};
use cipher::consts::U12;
use std::process;

#[derive(Debug)]
pub struct EncryptedData {
    pub Key: Vec<u8>,
    pub Nonce: Vec<u8>,
    // The tag is embedded within the cyphertext last 16 bytes is the tag
    pub cyphertext: Vec<u8>
}

pub struct DecryptedData {
    pub decryptedtext: String
}

pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], data: &Vec<u8>) -> EncryptedData {

    let key: &Key<Aes256Gcm> = key.into();
    let cypherstruct = Aes256Gcm::new(&key);

    let nonce: GenericArray<u8, U12> = GenericArray::clone_from_slice(nonce);

    let ciphertext = cypherstruct.encrypt(&nonce, data.as_ref()).unwrap(); 

    EncryptedData { Key: key.to_vec(), Nonce: nonce.to_vec(), cyphertext: ciphertext }
}

pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], cyphertext: &Vec<u8>) -> DecryptedData {

    let key: &Key<Aes256Gcm> = key.into();
    let cypherstruct = Aes256Gcm::new(&key);

    let nonce: GenericArray<u8, U12> = GenericArray::clone_from_slice(nonce);

    let decyptedtext = match cypherstruct.decrypt(&nonce, cyphertext.as_slice()) {
        Ok(result) => result,
        Err(_) => {
            println!("Incorrect Password");
            process::exit(1);
        },
    };

    DecryptedData { decryptedtext: String::from_utf8(decyptedtext).unwrap()}

}