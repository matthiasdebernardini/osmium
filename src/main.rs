#![allow(unused)]
use bip39::{self, Mnemonic};
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::{secp256k1::Secp256k1, XOnlyPublicKey};
use chrono::format::format;
use chrono::offset::Utc;
use clap::{arg, Command};
use fern::Dispatch;
use log::*;
use nostr::Keys;
use rand::{distributions::Standard, *};
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
use clap::Parser;
use read_input::prelude::*;
use age::secrecy::Secret;

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

fn handle_user(s: Option<String>, decryption_password: String) -> Result<(), Box<dyn Error>> {
    // println!("init user");
    // let base_dirs = BaseDirectories::new().expect("Need to initalize base dirs");
    // let home = base_dirs.get_config_home();
    // let home = home.to_str().expect("Could not convert").to_string();
    // let data_path = format!("{}/osmium/mnemonic.backup", home);
    // let config_path = format!("{}/osmium/osmium.toml", home);
    // let xdg_data = base_dirs.find_data_file(data_path);
    // let xdg_config = base_dirs.find_config_file(config_path);
    // println!("{xdg_data:?} {xdg_config:?}");
    let (xdg_data, xdg_config, _) = get_app_files()?;

    todo!("decrypt password");
    let mnemonic = std::fs::read_to_string(xdg_data)
        .expect("Could not read file to string");
    let mnemonic: Mnemonic =
        bip39::Mnemonic::from_str(&mnemonic).expect("Could not convert to mnemonic");
    let u = User::load_config(mnemonic, xdg_config);
    if s.is_some() {
        let new = s.unwrap();
        let index = new
            .split_ascii_whitespace()
            .next()
            .expect("Invalid")
            .parse::<usize>()
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
        let password = get_new_password(root, index);
        println!("{:?}", password.unwrap());
    }
    todo!("write to data file");
    Ok(())
}

fn handle_recovered_user(s: Option<String>) -> Result<User, Box<dyn Error>> {
    todo!()
}

fn handle_new_user() -> Result<User, Box<dyn Error>> {
    Ok(User::new())
}

fn get_app_files() -> Result<(PathBuf, PathBuf, PathBuf), Box<dyn Error>> {
    let base_dirs = BaseDirectories::new().expect("need to initalize base dirs");
    let home = base_dirs.get_config_home();
    let home = home.to_str().expect("Could not convert").to_string();
    let mnemonic_path = format!("{}/osmium/mnemonic.backup", home);
    let config_path = format!("{}/osmium/osmium.toml", home);
    let password_path = format!("{}/osmium/osmium.passwords", home);
    let xdg_data = base_dirs.find_data_file(mnemonic_path).ok_or("could not get data")?;
    let xdg_config = base_dirs.find_config_file(config_path).ok_or("could not get config")?;
    let xdg_passwords = base_dirs.find_data_file(password_path).ok_or("could not get password")?;
    Ok((xdg_data, xdg_config, xdg_passwords))
}
fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    init_log()?;

    match (cli.init, cli.recover) {
        (None, None) => {
            println!("Decrypt your data");
            let decryption_password = input::<String>().get();
            handle_user(cli.new, decryption_password);
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
            let u = handle_new_user()?;
            println!("Add an encryption password, so that if you device is compromised, an attacker won't be able to steal your data");
            let passphrase = input::<String>().get();

            let encrypted_data = {
                let plaintext = "st".as_bytes();
                let encryptor = age::Encryptor::with_user_passphrase(Secret::new(passphrase.to_owned()));
            
                let mut encrypted = vec![];
                let mut writer = encryptor.wrap_output(&mut encrypted)?;
                writer.write_all(plaintext)?;
                writer.finish()?;
            
                encrypted
            }; 
            let encrypted_config = {
                let plaintext = "st".as_bytes();
                let encryptor = age::Encryptor::with_user_passphrase(Secret::new(passphrase.to_owned()));
            
                let mut encrypted = vec![];
                let mut writer = encryptor.wrap_output(&mut encrypted)?;
                writer.write_all(plaintext)?;
                writer.finish()?;
            
                encrypted
            }; 
            let encrypted_passwords = {
                let plaintext = "st".as_bytes();
                let encryptor = age::Encryptor::with_user_passphrase(Secret::new(passphrase.to_owned()));
            
                let mut encrypted = vec![];
                let mut writer = encryptor.wrap_output(&mut encrypted)?;
                writer.write_all(plaintext)?;
                writer.finish()?;
            
                encrypted
            }; 
            todo!("initialize new user, then ask for registration")
        }
        (_, _) => {
            unreachable!("clap crate should prevent this executing this arm by making the arguments exclusive")
        }
    };
    // matches. .value_of("new").expect("Could not get new option");
    // let mut make_new: bool = false;
    // if make_new {}
    // let mut name = "";
    // let mut index = 0;
    // if new.is_empty() {
    //     make_new = false;
    // } else {
    //     make_new = true;
    //     index = new
    //         .split_ascii_whitespace()
    //         .next()
    //         .expect("Invalid")
    //         .parse::<usize>()
    //         .expect("Expected a number like 1 but could not get it");
    //     name = new
    //         .split_ascii_whitespace()
    //         .last()
    //         .expect("Expected a name like 'twitter' but could not get it");
    // }
    // let init_app = true;
    // // matches
    // //     .value_of("init")
    // //     .expect("Could not get init option")
    // //     .parse::<bool>()
    // //     .expect("Could not get true or false");
    // if init_app {
    //     let seed: Vec<u8> = rand::thread_rng().sample_iter(&Standard).take(32).collect();
    //     let mnemonic = bip39::Mnemonic::from_entropy(seed.as_ref())
    //         .expect("Could not make mnemonic")
    //         .to_string();
    //     info!("the following data needs to be backed up to paper with pencil");
    //     info!("without this data, it is impossible to recover your passwords");
    //     info!("{mnemonic:?}");
    //     let path = format!("/mnemonic.backup");
    //     let f = File::create(path).expect("Unable to create file");
    //     let mut f = BufWriter::new(f);
    //     f.write_all(mnemonic.as_bytes())
    //         .expect("Unable to write data");
    // }
    // if make_new {
    //     // avoids accidentaly using these keys in wallet software
    //     let network = bitcoin::Network::Regtest;
    //     let path = format!("/mnemonic.backup");
    //     let contents = fs::read_to_string(path)
    //         .expect("Something went wrong when reading the mnemonic backup");
    //     let seed = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, contents.as_str())?
    //         .to_entropy();
    //     let root = ExtendedPrivKey::new_master(network, &seed)?;
    //     info!("Root key: {}", root);
    //     let new_password = get_new_password(root, index)?;
    //     info!("new password for {name} with index {index}:");
    //     info!("{new_password}");
    // }
    Ok(())
}

fn get_new_password(
    root: ExtendedPrivKey,
    index: usize,
) -> Result<ExtendedPrivKey, Box<dyn Error>> {
    let secp = Secp256k1::new();
    let xprv =
        bip85::to_xprv(&secp, &root, index as u32).expect("Could not derive ExtendedPrivKey");
    Ok(xprv)
}

fn init_log() -> Result<(), Box<dyn Error>> {
    Ok(Dispatch::new()
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
        // .chain(log_file(format!("output_{}.log", Utc::now().timestamp()))?)
        .apply()?)
}

#[derive(Debug)]
struct User {
    config: PathBuf,
    registered: bool,
    mnemonic: Mnemonic,
    pubkey: XOnlyPublicKey,
}

trait New {
    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    fn configure() -> Result<PathBuf, Box<dyn Error>>;
    fn recover() -> Self;
    fn get_pubkey(mnemonic: &Mnemonic) -> XOnlyPublicKey;
    fn make_seed() -> String;
    fn new() -> Self;
    fn register(&self) -> bool;
    fn load_config(mnemonic: Mnemonic, path: PathBuf) -> Self;
}

impl New for User {
    fn configure() -> Result<PathBuf, Box<dyn Error>> {
        let xdg_dirs = BaseDirectories::with_prefix("osmium")?;
        todo!("make sure its encrypted");
        todo!("https://kerkour.com/rust-file-encryption");
        Ok(xdg_dirs.place_config_file("config.toml")?)
    }

    fn make_seed() -> String {
        let seed: Vec<u8> = rand::thread_rng().sample_iter(&Standard).take(32).collect();
        bip39::Mnemonic::from_entropy(seed.as_ref())
            .expect("Could not make mnemonic")
            .to_string()
    }

    fn register(&self) -> bool {
        todo!()
    }

    fn get_pubkey(mnemonic: &Mnemonic) -> XOnlyPublicKey {
        let root_key = bitcoin::util::bip32::ExtendedPrivKey::new_master(
            bitcoin::Network::Bitcoin,
            &mnemonic.to_entropy_array().0,
        )
        .unwrap();
        let path = bitcoin::util::bip32::DerivationPath::from_str("m/44'/1237'/0'/0/0").unwrap();
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let child_xprv = root_key.derive_priv(&secp, &path).unwrap();
        // let secret_key = Keys::try_from(child_xprv.private_key).unwrap();
        let keys = Keys::new(child_xprv.private_key.into());
        keys.public_key()
    }

    fn new() -> Self {
        let config = User::configure().expect("can not make config for new user");
        let seed = User::make_seed();
        let mnemonic =
            bip39::Mnemonic::parse_in_normalized(bip39::Language::English, seed.as_str())
                .expect("cannot make mnemonic")
                .to_string();
        // let passphrase= Some("".to_string());
        // .to_entropy();
        let mnemonic: Mnemonic = bip39::Mnemonic::from_str(&mnemonic).unwrap();
        // let seed  = mnemonic.to_entropy();
        // //  .to_seed(passphrase.map(|p| p.into()).unwrap_or_default());
        // let root_key = bitcoin::util::bip32::ExtendedPrivKey::new_master(bitcoin::Network::Bitcoin, &mnemonic.to_entropy_array().0).unwrap();
        // let path = bitcoin::util::bip32::DerivationPath::from_str("m/44'/1237'/0'/0/0").unwrap();
        // let secp = bitcoin::secp256k1::Secp256k1::new();
        // let child_xprv = root_key.derive_priv(&secp, &path).unwrap();
        // // let secret_key = Keys::try_from(child_xprv.private_key).unwrap();
        // let keys = Keys::new(child_xprv.private_key.into());
        // let pubkey = keys.public_key();
        let pubkey = User::get_pubkey(&mnemonic);

        User {
            config,
            registered: true,
            mnemonic,
            pubkey,
        }
    }

    fn recover() -> Self {
        todo!()
    }

    fn load_config(mnemonic: Mnemonic, config: PathBuf) -> Self {
        let pubkey = User::get_pubkey(&mnemonic);
        User {
            config,
            registered: false,
            mnemonic,
            pubkey,
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Ok;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_add() {
        let user = User::new();
        assert_eq!(User::make_seed(), "");
    }
    #[test]
    fn configure() {
        let user = User::new();
        User::configure();
        panic!()
    }
}
