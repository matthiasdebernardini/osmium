#![allow(unused)]
use bip39::{self, Mnemonic};
use bitcoin::util::bip32::ExtendedPrivKey;
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
use clap::Parser;
use nostr::util::nips::nip19::ToBech32;
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

fn handle_user(s: Option<String>, decryption_password: String) -> Result<(), Box<dyn Error>> {
    let app_files = get_app_files()?;

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
        let password = get_new_password(root, index);
        println!("{:?}", password.unwrap());
    }
    // update password data file
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open("my-file")
        .unwrap();

    if let Err(e) = writeln!(file, "A new line!") {
        eprintln!("Couldn't write to file: {}", e);
    }
    todo!("write to data file");
    Ok(())
}

fn handle_recovered_user(s: Option<String>) -> Result<User, Box<dyn Error>> {
    todo!()
}

struct AppFiles {
    app_mnemonic: PathBuf,
    app_config: PathBuf,
    app_passwords: PathBuf,
    app_log: PathBuf,
}

fn get_app_files() -> Result<AppFiles, Box<dyn Error>> {
    let base_dirs = BaseDirectories::new().expect("need to initalize base dirs");
    let home = base_dirs.get_config_home();
    let home = home.to_str().expect("Could not convert").to_string();

    let mnemonic_path = format!("{}/osmium/mnemonic.backup", home);
    let config_path = format!("{}/osmium/osmium.toml", home);
    let password_path = format!("{}/osmium/osmium.passwords", home);

    let app_mnemonic = base_dirs
        .find_data_file(mnemonic_path)
        .ok_or("could not get data")?;
    let app_config = base_dirs
        .find_config_file(config_path)
        .ok_or("could not get config")?;
    let app_passwords = base_dirs
        .find_data_file(password_path)
        .ok_or("could not get password")?;

    Ok(AppFiles {
        app_mnemonic,
        app_config,
        app_passwords,
        app_log: PathBuf::default(),
    })
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
            let app_files = get_app_files()?;
            std::fs::write(
                app_files.app_config,
                format!("{:?}\n{:?}", u.pubkey, u.registered),
            );
            std::fs::write(app_files.app_mnemonic, format!("{:?}", u.mnemonic));
            todo!("initialize new user, then ask for registration")
        }
        (_, _) => {
            unreachable!("clap crate should prevent this executing this arm by making the arguments exclusive")
        }
    };
    Ok(())
}

fn get_new_password(root: ExtendedPrivKey, index: u32) -> Result<ExtendedPrivKey, Box<dyn Error>> {
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
        // .chain(io::stderr())
        .chain(log_file(format!("osmium_{}.log", Utc::now().timestamp()))?)
        .apply()?)
}

#[derive(Debug)]
struct User {
    config: PathBuf,
    registered: bool,
    mnemonic: Mnemonic,
    pubkey: String,
}

trait NewInstance {
    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    fn configure() -> Result<PathBuf, Box<dyn Error>>;
    fn recover() -> Self;
    fn get_pubkey(mnemonic: &Mnemonic) -> Result<String, Box<dyn Error>>;
    fn make_mnemonic() -> Result<String, Box<dyn Error>>;
    fn new() -> Result<Self, Box<dyn Error>>
    where
        Self: Sized;
    fn register(&self) -> bool;
    fn load_config(mnemonic: Mnemonic, path: PathBuf) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized;
}

impl NewInstance for User {
    fn configure() -> Result<PathBuf, Box<dyn Error>> {
        let xdg_dirs = BaseDirectories::with_prefix("osmium")?;
        Ok(xdg_dirs.place_config_file("config.toml")?)
    }

    fn make_mnemonic() -> Result<String, Box<dyn Error>> {
        let entropy: Vec<u8> = rand::thread_rng().sample_iter(&Standard).take(32).collect();
        let mut needs_double_checking = true;
        let mut passphrase = String::new();
        println!("Add a passphrase, so that its impossible for the user to steal your data");
        while needs_double_checking {
            let mut once = prompt_password("Input your BIP39 Passphrase, to encrypt your seed")?;
            let mut twice = prompt_password("Input your passphrase a second time")?;
            if once.eq(&twice) {
                passphrase = once.clone();
                needs_double_checking = false;
                once.zeroize();
                twice.zeroize();
            }
        }
        println!("CRITICAL INFO: STORE PASSPHRASE SECURELY");
        println!("WITHOUT IT - YOUR PASSWORDS ARE GONE");
        let seed = bip39::Mnemonic::from_entropy(entropy.as_ref())
            .expect("Could not make mnemonic")
            .to_seed_normalized(&passphrase)
            .to_vec();
        passphrase.zeroize();
        let seed = std::str::from_utf8(&seed).unwrap();
        let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, seed)
            .expect("cannot make mnemonic")
            .to_string();
        Ok(mnemonic)
    }

    fn register(&self) -> bool {
        todo!()
    }

    fn get_pubkey(mnemonic: &Mnemonic) -> Result<String, Box<dyn Error>> {
        let root_key = bitcoin::util::bip32::ExtendedPrivKey::new_master(
            bitcoin::Network::Bitcoin,
            &mnemonic.to_entropy_array().0,
        )?;
        let path = bitcoin::util::bip32::DerivationPath::from_str("m/44'/1237'/0'/0/0")?;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let child_xprv = root_key.derive_priv(&secp, &path)?;
        // let secret_key = Keys::try_from(child_xprv.private_key).unwrap();
        let keys = Keys::new(child_xprv.private_key.into());
        let pubkey = keys.public_key().to_bech32()?;
        Ok(pubkey)
    }

    fn new() -> Result<Self, Box<dyn Error>> {
        let config = User::configure().expect("can not make config for new user");
        let mnemonic: Mnemonic = bip39::Mnemonic::from_str(&User::make_mnemonic()?)?;
        let pubkey = User::get_pubkey(&mnemonic)?;
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
        let pubkey = User::get_pubkey(&mnemonic)?;
        let config = PathBuf::from(config);
        Ok(User {
            config,
            registered: false,
            mnemonic,
            pubkey,
        })
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
        assert_eq!(User::make_mnemonic().unwrap(), "");
    }
    #[test]
    fn configure() {
        let user = User::new();
        User::configure();
        panic!()
    }
}
