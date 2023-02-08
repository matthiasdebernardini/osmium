#![allow(unused)]
extern crate core;

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
use reqwest::blocking::get;
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
use anyhow::Context;
// use anyhow::Ok;
use carbonado::{decode, encode, utils::init_logging, verify_slice};
use clap::Parser;
use hex::ToHex;
use itertools::{sorted, Itertools};
use nostr::util::nips::nip19::ToBech32;
use reqwest::header;
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
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

#[derive(Debug)]
struct AppFiles {
    mnemonic: PathBuf,
    config: PathBuf,
    passwords: PathBuf,
    log: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_log()?;
    match (cli.init, cli.recover) {
        // initialized user wants to make new password
        (None, None) => {
            // println!("Decrypt your data");
            handle_user(cli.new)
            // Ok(())
        }
        // user wants to recover passwords with mnemonic backup
        (None, Some(p)) => {
            handle_recovered_user(None);
            // todo!(
            //     "check path for seed,
            //     warn user about putting seed in file then providing path to file,
            //     then ask for registration if registered already then fetch API"
            // )
            Ok(())
        }
        // uninitialized user wants to start using osmium
        (Some(_), None) => {
            let u = User::new()?;
            Ok(())
        }
        (_, _) => {
            unreachable!(
                "clap crate should prevent this arm executing by making the arguments exclusive"
            )
            // Ok(())
        }
    }
    // panic!()
}

#[derive(Debug)]
struct User {
    config: PathBuf,
    // change to LN invoice paid
    registered: bool,
    mnemonic: Mnemonic,
    pubkey: String,
    //todo language
}

impl NewInstance for User {
    fn make_app_file(path: &PathBuf, contents: &str) -> anyhow::Result<()> {
        let path = path.to_str().expect("Could not get file path");
        std::fs::write(path, contents).map_err(|e| e.into())
    }

    fn get_app_files() -> anyhow::Result<AppFiles> {
        let base_dirs = BaseDirectories::with_prefix("osmium")?;

        let home = base_dirs.get_config_home();
        let home = home.to_str().expect("Could not convert");

        let mnemonic = format!("{home}mnemonic.backup");
        let config = format!("{home}osmium.toml");
        let password = format!("{home}osmium.passwords");

        let mnemonic = base_dirs.place_config_file(mnemonic)?;
        let config = base_dirs.place_config_file(config)?;
        let passwords = base_dirs.place_config_file(password)?;

        Ok(AppFiles {
            mnemonic,
            config,
            passwords,
            log: PathBuf::default(),
        })
    }

    fn configure(mnemonic: &Mnemonic) -> anyhow::Result<PathBuf> {
        let base_dirs = BaseDirectories::with_prefix("osmium")?;
        let app_mnemonic = User::get_app_files()?.mnemonic;
        let contents = encrypt(mnemonic.to_string())?;
        User::make_app_file(&app_mnemonic, &contents)?;
        Ok(base_dirs.get_config_home())
    }

    fn make_mnemonic() -> anyhow::Result<Mnemonic> {
        bip39::Mnemonic::generate(12).context("Could not generate mnemonic")

        // .map_err(|e| format!("Could not generate 12 word password because: {e}").into())
    }

    fn register(&self) -> bool {
        println!("Would you like to pay for encrypted cloud backups?");
        println!("The Osmium Service can store a copy of your encrypted metadata, your passwords are never stored and will not leave the device.");
        println!("Enter Y/y to accept or Enter to avoid.");
        println!("The service is affordable and secure, we never store your passwords.");
        todo!()
    }

    fn get_pubkey(extended_private_key: &ExtendedPrivKey) -> anyhow::Result<String> {
        Keys::new(extended_private_key.private_key)
            .public_key()
            .to_bech32()
            .map_err(|e| e.into())
    }

    fn new() -> anyhow::Result<Self> {
        let mnemonic: Mnemonic = User::make_mnemonic()?;
        let extended_private_key = User::get_extended_private_key(&mnemonic)?;
        let pubkey = User::get_pubkey(&extended_private_key)?;
        let config = User::configure(&mnemonic)?;
        let u = User {
            config,
            registered: true,
            mnemonic,
            pubkey,
        };

        Ok(u)
    }

    fn recover() -> Self {
        todo!()
    }

    fn load_config(mnemonic: Mnemonic, config: PathBuf) -> anyhow::Result<Self>
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

    fn update_passwords_file(path: PathBuf) -> anyhow::Result<()> {
        todo!()
    }

    fn get_extended_private_key(mnemonic: &Mnemonic) -> anyhow::Result<ExtendedPrivKey> {
        let passphrase = get_passphrase().expect("should never fail");
        // TODO should I use to normalized?
        ExtendedPrivKey::new_master(Network::Regtest, &mnemonic.to_seed(passphrase))
            .map_err(|e| e.into())
    }

    fn get_new_password(&self, name: &str) -> anyhow::Result<String> {
        let base_dirs = BaseDirectories::with_prefix("osmium")?;
        let passwords_appfile = User::get_app_files()?.passwords;
        let contents = match fs::read_to_string(passwords_appfile.clone()) {
            Ok(a) => a,
            Err(_) => String::new(),
        };
        // the index that we use is the relative newline position of the name in the file
        let index = match contents.lines().position(|n| n == name) {
            None => contents.lines().count() as u32 + 1,
            Some(i) => i as u32 + 1,
        };
        let mut n = Vec::new();
        writeln!(&mut n, "{}", name);
        let n = std::str::from_utf8(&n)?;

        // todo make sorted
        let contents = contents
            .lines()
            .chain(std::iter::once(n))
            .sorted()
            .collect::<String>();

        User::make_app_file(&passwords_appfile, &contents);
        let passphrase = get_passphrase().expect("should never fail");
        // TODO should I use to normalized?
        let root =
            ExtendedPrivKey::new_master(Network::Regtest, &self.mnemonic.to_seed(passphrase))?;
        let secp = Secp256k1::new();
        let key = bip85::to_xprv(&secp, &root, index).expect("to never fail");
        let a = key
            .to_priv()
            .to_bytes()
            .into_iter()
            .map(|b| {
                let a: u32 = u32::from(b);
                let a = match a {
                    u32::MIN..=32 => a + 33,
                    33..=126 => a,
                    127..=u32::MAX => {
                        let a = a % 126;
                        if a < 33 {
                            a + 33
                        } else {
                            a
                        }
                    }
                };
                char::from_u32(a).unwrap()
            })
            .collect::<Vec<char>>();
        let s = String::from_iter(a);

        Ok(s)
    }
}

#[derive(Deserialize, Serialize)]
struct Efficient<'a> {
    #[serde(with = "serde_bytes")]
    bytes: &'a [u8],

    #[serde(with = "serde_bytes")]
    byte_buf: Vec<u8>,
}

#[cfg(test)]
mod tests {
    // use core::panicking::panic;
    // use anyhow::Ok;
    use anyhow::anyhow;
    // use bitcoin::secp256k1::PublicKey;
    use carbonado::utils::bech32_decode;
    use rand::thread_rng;
    use secp256k1::Error as SecpError;
    use secp256k1::PublicKey;
    use secp256k1::SecretKey;
    use std::result::Result::Ok;
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    // use ecies::utils::generate_keypair;
    #[test]
    fn test_init() {
        let user = User::new().unwrap();
        println!("User: {user:?}");
    }
    #[test]
    fn configure() {
        let user = User::new().unwrap();
        let new_password = user.get_new_password("test").unwrap();
        println!("{}", new_password);
        let new_password = user.get_new_password("test1").unwrap();

        println!("{}", new_password);
    }
    // #[test]
    // fn test_carbonado() {
    //     let input = "hello".as_bytes();
    //     let user = User::new().unwrap();
    //
    //     let a = bech32_decode(&user.pubkey).unwrap().1;
    //     let pk = XOnlyPublicKey::from_slice(&a).unwrap();
    //
    //     let sk = SecretKey::random(&mut thread_rng());
    //     let pk = PublicKey::from_secret_key(&sk);
    //     let (encoded, hash, encode_info) = match encode(&pk.serialize(), input, 15) {
    //         Ok(a) => (a),
    //         Err(e) => panic!("Could not encode due to {}", e),
    //     };
    //
    //     println!("encoded: {:?}", encoded);
    //     println!("hash: {:?}", hash);
    //     println!("encode_info: {:?}", encode_info);
    // }
}

//TODO: implement real mocking
fn get_passphrase() -> anyhow::Result<String> {
    // if test {
    return Ok("test".to_string());
    // }
    // let mut needs_double_checking = true;
    // let mut passphrase = String::new();
    // while needs_double_checking {
    //     let mut once =
    //         prompt_password("Input your BIP39 Passphrase: ")?;
    //     let mut twice = prompt_password("Input your BIP39 passphrase a second time: ")?;
    //     if once.eq(&twice) {
    //         passphrase = once;
    //         needs_double_checking = false;
    //         twice.zeroize();
    //     }
    // }
    // println!("CRITICAL INFO: STORE PASSPHRASE SECURELY");
    // println!("MNEMONIC + PASSPHRASE = PASSWORDS");
    // println!("NOBODY CAN HELP IF YOU LOSE IT - THAT'S WHY IT WORKS IN THE FIRST PLACE");
    // Ok(passphrase)
}

fn encrypt(plaintext: String) -> anyhow::Result<String> {
    let encryptor = age::Encryptor::with_user_passphrase(Secret::new(get_passphrase()?));
    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    writer.write_all(plaintext.as_bytes())?;
    writer.finish()?;
    // Ok(hex::encode(encrypted))
    Ok(plaintext)
}

fn decrypt(encrypted: Vec<u8>) -> anyhow::Result<String> {
    let decrypted = {
        let decryptor = match age::Decryptor::new(&encrypted[..])? {
            age::Decryptor::Passphrase(d) => d,
            _ => unreachable!(),
        };
        let mut decrypted = vec![];
        let mut reader = decryptor.decrypt(&Secret::new(get_passphrase()?), None)?;
        reader.read_to_end(&mut decrypted);
        decrypted
    };

    Ok(format!("{:x?}", encrypted))

    // String::from_utf8(decrypted).map_err(|e| e.into())
}

// TODO: add log file to path
fn init_log() -> anyhow::Result<()> {
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
        .map_err(|e| e.into())
}

fn handle_user(new: Option<String>) -> anyhow::Result<()> {
    let app_files = User::get_app_files()?;
    // println!("app files: {app_files:?}");

    // todo!("decrypt password");
    let mnemonic = std::fs::read_to_string(app_files.mnemonic)?;
    // let mnemonic = decrypt(mnemonic.into_bytes())?;
    // println!("mnemonic: {mnemonic:?}");
    let mnemonic: Mnemonic = bip39::Mnemonic::from_str(&mnemonic)?;
    // .expect("Could not convert to mnemonic");
    let u = User::load_config(mnemonic, app_files.config)?;
    match new {
        Some(n) => {
            let password = u.get_new_password(&n)?;
            Ok(println!("{}", password))
        }
        None => Err(anyhow::anyhow!(
            "No value to make a new password with, pass a name with the n flag"
        )),
    }
    // update password data file
    // let mut file = OpenOptions::new()
    //     .write(true)
    //     .append(true)
    //     .open("my-file")?;
    //
    // if let Err(e) = writeln!(file, "A new line!") {
    //     eprintln!("Couldn't write to file: {}", e);
    // }
    // todo!("write to data file");
    // Ok(())
}

fn handle_recovered_user(s: Option<String>) -> anyhow::Result<User> {
    todo!()
}

trait NewInstance {
    /// .
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    fn configure(mnemonic: &Mnemonic) -> anyhow::Result<PathBuf>;
    fn recover() -> Self;
    fn get_pubkey(extended_private_key: &ExtendedPrivKey) -> anyhow::Result<String>;
    fn make_mnemonic() -> anyhow::Result<Mnemonic>;
    fn new() -> anyhow::Result<Self>
    where
        Self: Sized;
    fn register(&self) -> bool;
    fn load_config(mnemonic: Mnemonic, path: PathBuf) -> anyhow::Result<Self>
    where
        Self: Sized;
    fn get_app_files() -> anyhow::Result<AppFiles>;
    fn make_app_file(path: &PathBuf, contents: &str) -> anyhow::Result<()>;
    fn update_passwords_file(path: PathBuf) -> anyhow::Result<()>;
    fn get_extended_private_key(mnemonic: &Mnemonic) -> anyhow::Result<ExtendedPrivKey>;
    fn get_new_password(&self, name: &str) -> anyhow::Result<String>;
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
