#![allow(unused)]
use bip39::serde::__private::de::TagOrContentFieldVisitor;
use bip39::{self, Language, Mnemonic};
use bitcoin::secp256k1::SecretKey;
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::Network;
use bitcoin::{secp256k1::Secp256k1, XOnlyPublicKey};
use chrono::format::format;
use chrono::offset::Utc;
use clap::{arg, Command};
use fern::{log_file, Dispatch};
use log::*;
use nostr::url::quirks::password;
use nostr::Keys;
use rand::{distributions::Standard, *};
use std::ops::Deref;
use std::str::FromStr;
use std::{
    borrow::Cow,
    env,
    error::Error,
    fs::{self, File},
    io::{self, BufWriter, Read, Write},
    path::{Path, PathBuf},
};
use xdg::BaseDirectories;
mod bip85;
use age::secrecy::Secret;
use age::stream::StreamWriter;
use clap::Parser;
use nostr::util::nips::nip19::ToBech32;
use reqwest::header;
use rpassword::prompt_password;
use std::fs::OpenOptions;
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    author = "Matthias Debernardini <m.f.debern@protonmail.com>",
    version = "0.0.1",
    about = "CLI for the Osmium password manager service"
)]
struct Cli {
    #[arg(short = 'i', exclusive = true)]
    init: Option<bool>,
    #[arg(short = 'n', exclusive = true)]
    new: Option<String>,
    #[arg(short = 'r', exclusive = true)]
    recover: Option<PathBuf>,
}

struct AppFiles {
    app_mnemonic: PathBuf,
    app_config: PathBuf,
    app_passwords: PathBuf,
    app_log: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    init_log()?;

    match (cli.init, cli.recover) {
        (None, None) => {
            println!("Decrypt your data");
            handle_user(cli.new, todo!());
            todo!("check if path to config exists, then check for args.new");
        }
        (None, Some(p)) => {
            handle_recovered_user(None);
            todo!(
                "check path for seed, 
                warn user about putting seed in file then providing path to file, 
                then ask for registration if registered already then fetch API"
            )
        }
        (Some(_), None) => {
            let u = User::new()?;
            let app_files = User::get_app_files()?;
            let contents = encrypt(&format!("{:?}", u.pubkey), "")?;
            User::make_app_files(app_files.app_config, &format!("{contents:?}"))
                .map_err(|e| e.into())
            // todo!("initialize new user, then ask for registration")
            // let contents = encrypt(&format!("{:?}", u.mnemonic), "")

        }
        (_, _) => {
            unreachable!(
                "clap crate should prevent this arm executing by making the arguments exclusive"
            )
        }
    }
    // Ok(())
}

fn get_new_password(root: ExtendedPrivKey, index: u32) -> Result<ExtendedPrivKey, Box<dyn Error>> {
    let secp = Secp256k1::new();
    bip85::to_xprv(&secp, &root, index).map_err(|e| format!("{e}").into())
}

#[derive(Debug)]
struct User {
    config: PathBuf,
    // change to LN invoice paid
    registered: bool,
    mnemonic: Mnemonic,
    pubkey: String,
    //language
    
}

impl NewInstance for User {
    fn make_app_files(path: PathBuf, contents: &str) -> Result<(), std::io::Error> {
        let path = path.to_str().expect("Could not get file path");
        std::fs::write(path, contents)
    }

    fn get_app_files() -> Result<AppFiles, Box<dyn Error>> {
        let base_dirs = BaseDirectories::new()?;
        let config_home = base_dirs.create_config_directory("osmium")?;
        let home = base_dirs.get_config_home();
        let home = home.to_str().expect("Could not convert").to_string();

        let mnemonic_path = format!("{}/osmium/mnemonic.backup", home);
        let config_path = format!("{}/osmium/osmium.toml", home);
        let password_path = format!("{}/osmium/osmium.passwords", home);

        let app_mnemonic = base_dirs.place_config_file(mnemonic_path)?;
        let app_config = base_dirs.place_config_file(config_path)?;
        let app_passwords = base_dirs.place_config_file(password_path)?;

        Ok(AppFiles {
            app_mnemonic,
            app_config,
            app_passwords,
            app_log: PathBuf::default(),
        })
    }
    fn configure() -> Result<PathBuf, Box<dyn Error>> {
        let xdg_dirs = BaseDirectories::with_prefix("osmium")?;
        Ok(xdg_dirs.place_config_file("config.toml")?)
    }
    fn make_mnemonic() -> Result<Mnemonic, Box<dyn Error>> {
        bip39::Mnemonic::generate(12).map_err(|e| e.into())
    }
    fn register(&self) -> bool {
        todo!()
    }
    fn get_pubkey(extended_private_key: &ExtendedPrivKey) -> Result<String, Box<dyn Error>> {
        // let root_key = bitcoin::util::bip32::ExtendedPrivKey::new_master(
        //     bitcoin::Network::Bitcoin,
        //     &mnemonic.to_entropy_array().0,
        // )?;
        // let path = bitcoin::util::bip32::DerivationPath::from_str("m/44'/1237'/0'/0/0")?;
        // let secp = bitcoin::secp256k1::Secp256k1::new();
        // let child_xprv = root_key.derive_priv(&secp, &path)?;
        // let secret_key = Keys::try_from(child_xprv.private_key).unwrap();
        let secret_key = SecretKey::from_str(extended_private_key.to_string().as_str())?;
        let keys = Keys::new(secret_key);
        keys.public_key().to_bech32().map_err(|e| e.into())
        // Ok(pubkey)
    }
    fn new() -> Result<Self, Box<dyn Error>> {
        let config = User::configure().expect("can not make config for new user");
        let mnemonic: Mnemonic = User::make_mnemonic()?;
        let extended_private_key = User::get_extended_private_key(&mnemonic)?;
        let pubkey = User::get_pubkey(&extended_private_key)?;
        Ok(User {
            config,
            registered: true,
            mnemonic,
            pubkey,
        })
    }
    fn recover() -> Self {
        todo!()
    }
    fn load_config(mnemonic: Mnemonic, config: PathBuf) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
    {
        let extended_private_key = User::get_extended_private_key(&mnemonic)?;
        let pubkey = User::get_pubkey(&extended_private_key)?;
        let config = PathBuf::from(config);
        Ok(User {
            config,
            registered: false,
            mnemonic,
            pubkey,
        })
    }

    fn update_passwords_file(path: PathBuf) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    fn get_extended_private_key(mnemonic: &Mnemonic) -> Result<ExtendedPrivKey, Box<dyn Error>> {
        let passphrase = get_passphrase()?;
        ExtendedPrivKey::new_master(Network::Testnet, &mnemonic.to_seed(passphrase))
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Ok;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_mnemonic() {
        let user = User::new();
        panic!()
    }
    #[test]
    fn configure() {
        let user = User::new();
        User::configure();
        panic!()
    }
}

fn get_passphrase() -> Result<String, Box<dyn Error>> {
    let mut needs_double_checking = true;
    let mut passphrase = String::new();
    println!("Add a passphrase, so that its impossible for the user to steal your data");
    while needs_double_checking {
        let mut once =
            prompt_password("Input your BIP39 Passphrase, to encrypt your mnemonic phrase")?;
        let mut twice = prompt_password("Input your passphrase a second time ")?;
        if once.eq(&twice) {
            passphrase = once;
            needs_double_checking = false;
            twice.zeroize();
        }
    }
    println!("CRITICAL INFO: STORE PASSPHRASE SECURELY");
    println!("MNEMONIC + PASSPHRASE = PASSWORDS");
    println!("NOBODY CAN HELP IF YOU LOSE IT - THAT'S WHY IT WORKS IN THE FIRST PLACE");
    Ok(passphrase)
}

fn encrypt(buf: &str, path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let text = "aa";
    let mut buffer = File::create(path)?;

    let passphrase = get_passphrase()?;

    let encryptor = age::Encryptor::with_user_passphrase(Secret::new(passphrase.to_owned()));

    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    buffer.write_all(&mut text.as_bytes())?;
    // buffer.finish()?;

    Ok(buf.as_bytes().to_vec())
}

fn decrypt_file(path: PathBuf) -> Result<(), Box<dyn Error>> {
    todo!()
}

fn init_log() -> Result<(), SetLoggerError> {
    Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                Utc::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(LevelFilter::Debug)
        .chain(io::stderr())
        // .chain(log_file(format!("osmium_{}.log", Utc::now().timestamp()))?)
        .apply()
}

fn handle_user(s: Option<String>, decryption_password: String) -> Result<(), Box<dyn Error>> {
    let app_files = User::get_app_files()?;

    todo!("decrypt password");
    let mnemonic =
        std::fs::read_to_string(app_files.app_mnemonic).expect("Could not read file to string");
    let mnemonic: Mnemonic =
        bip39::Mnemonic::from_str(&mnemonic).expect("Could not convert to mnemonic");
    let u = User::load_config(mnemonic, app_files.app_config)?;
    if s.is_some() {
        let new = s.unwrap();
        let index = new
            .split_ascii_whitespace()
            .next()
            .expect("Invalid")
            .parse::<u32>()
            .expect("Expected a number like 1 but could not get it");
        let name = new
            .split_ascii_whitespace()
            .last()
            .expect("Expected a name like 'twitter' but could not get it");
        let network = bitcoin::Network::Regtest;
        let seed = bip39::Mnemonic::parse_in_normalized(
            bip39::Language::English,
            u.mnemonic.to_string().as_str(),
        )?
        .to_entropy();
        let root = ExtendedPrivKey::new_master(network, &seed)?;
        let password = get_new_password(root, index)?;
        println!("{:?}", password);
    }
    // update password data file
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open("my-file")?;

    if let Err(e) = writeln!(file, "A new line!") {
        eprintln!("Couldn't write to file: {}", e);
    }
    todo!("write to data file");
    Ok(())
}

fn handle_recovered_user(s: Option<String>) -> Result<User, Box<dyn Error>> {
    todo!()
}
trait NewInstance {
    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    fn configure() -> Result<PathBuf, Box<dyn Error>>;
    fn recover() -> Self;
    fn get_pubkey(extended_private_key: &ExtendedPrivKey) -> Result<String, Box<dyn Error>>;
    fn make_mnemonic() -> Result<Mnemonic, Box<dyn Error>>;
    fn new() -> Result<Self, Box<dyn Error>>
    where
        Self: Sized;
    fn register(&self) -> bool;
    fn load_config(mnemonic: Mnemonic, path: PathBuf) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized;
    fn get_app_files() -> Result<AppFiles, Box<dyn Error>>;
    fn make_app_files(path: PathBuf, contents: &str) -> Result<(), std::io::Error>;
    fn update_passwords_file(path: PathBuf) -> Result<(), Box<dyn Error>>;
    fn get_extended_private_key(mnemonic: &Mnemonic) -> Result<ExtendedPrivKey, Box<dyn Error>>;
}

fn request() -> Result<(), Box<dyn std::error::Error>> {
    let mut headers = header::HeaderMap::new();
    headers.insert("Content-Type", "application/json".parse().unwrap());

    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let res = client.post("http://localhost:3000/4deb433c53cf800d0ba1501e416569902ac41d04f5587b2aed8e34ed35ebc512")
        .headers(headers)
        .body(r#"
{
  "Id": 12345,
  "Customer": "John Smith",
  "Quantity": 1,
  "Price": 10.00
}

"#
        )
        .send()?
        .text()?;
    println!("{}", res);

    Ok(())
}
