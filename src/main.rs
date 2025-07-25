mod enc_dec;
mod kdf;
use crate::file_man::{AccountDetails, decrypt_data, encrypt_data};
mod file_man;
use dirs;
use std::fs;
mod cli;
use cli::prompt;
use rpassword;

fn main() {
    let config = dirs::config_local_dir().unwrap().join("passkeep");
    let file_path = config.join("enc.bin");

    match config.exists() {
        true => {}
        false => match fs::create_dir_all(&config) {
            Ok(_) => println!("Directory created at {}", &config.display()),
            Err(e) => panic!("failded to create directory: {}", e),
        },
    }
    let args = cli::parse();

    let mut password = rpassword::prompt_password("Enter your master password: ").unwrap();

    match file_path.exists() {
        true => {}
        false => {
            let data = "{}".to_string();
            encrypt_data(file_path.as_path(), &password, data);
        }
    }

    let mut file_hash_map = decrypt_data(&file_path.as_path(), &password);

    if args.get_flag("Remove-All") {
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
        if let Some(entry) = file_hash_map.get(account.as_str()) {
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
        let comments = prompt("comments: ");

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
