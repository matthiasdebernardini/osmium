use bitcoin::{secp256k1::Secp256k1, XOnlyPublicKey};
use bitcoin::util::bip32::ExtendedPrivKey;
use anyhow::Result;
use bip39::{self, Mnemonic};
// use bip85::*;
use chrono::offset::Utc;
use clap::{arg, Command};
use fern::Dispatch;
use log::*;
use rand::{distributions::Standard, *};
use std::{
    env,
    error::Error,
    fs::{self, File},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf}, borrow::Cow,
};
use std::str::FromStr;
use xdg::BaseDirectories;
use nostr::{ Keys };
mod bip85;
fn main() -> Result<(), Box<dyn Error>> {
    let u = User::new();
    let _matches = Command::new("osmium")
        .version("0.0.1")
        .author("Matthias Debernardini <m.f.debern@protonmail.com>")
        .arg(arg!(--init <BOOL> "path to load configuration file").default_missing_value("false"))
        .arg(arg!(--new <INDEX_NAME> "like '0 titter' but with a space").default_missing_value(""))
        .get_matches();
    init_log()?;
    let new = "".to_owned();
    // matches. .value_of("new").expect("Could not get new option");
    let mut make_new: bool = false;
    if make_new {}
    let mut name = "";
    let mut index = 0;
    if new.is_empty() {
        make_new = false;
    } else {
        make_new = true;
        index = new
            .split_ascii_whitespace()
            .next()
            .expect("Invalid")
            .parse::<usize>()
            .expect("Expected a number like 1 but could not get it");
        name = new
            .split_ascii_whitespace()
            .last()
            .expect("Expected a name like 'twitter' but could not get it");
    }
    let init_app = true;
    // matches
    //     .value_of("init")
    //     .expect("Could not get init option")
    //     .parse::<bool>()
    //     .expect("Could not get true or false");
    if init_app {
        let seed: Vec<u8> = rand::thread_rng().sample_iter(&Standard).take(32).collect();
        let mnemonic = bip39::Mnemonic::from_entropy(seed.as_ref())
            .expect("Could not make mnemonic")
            .to_string();
        info!("the following data needs to be backed up to paper with pencil");
        info!("without this data, it is impossible to recover your passwords");
        info!("{mnemonic:?}");
        let path = format!("/mnemonic.backup");
        let f = File::create(path).expect("Unable to create file");
        let mut f = BufWriter::new(f);
        f.write_all(mnemonic.as_bytes())
            .expect("Unable to write data");
    }
    if make_new {
        // avoids accidentaly using these keys in wallet software
        let network = bitcoin::Network::Regtest;
        let path = format!("/mnemonic.backup");
        let contents = fs::read_to_string(path)
            .expect("Something went wrong when reading the mnemonic backup");
        let seed = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, contents.as_str())?
            .to_entropy();
        let root = ExtendedPrivKey::new_master(network, &seed)?;
        info!("Root key: {}", root);
        let new_password = get_new_password(root, index)?;
        info!("new password for {name} with index {index}:");
        info!("{new_password}");
    }
    Ok(())
}

fn get_new_password(
    root: ExtendedPrivKey,
    index: usize,
) -> Result<ExtendedPrivKey, Box<dyn Error>> {
    let secp = Secp256k1::new();
    let xprv = bip85::to_xprv(&secp, &root, index as u32).expect("Could not derive ExtendedPrivKey");
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
    fn get_pubkey(mnemonic: &Mnemonic) -> XOnlyPublicKey;
    fn make_seed() -> String;
    fn new() -> Self;
    fn register(&self) -> bool;
}

impl New for User {
    fn configure() -> Result<PathBuf, Box<dyn Error>> {
        let xdg_dirs = BaseDirectories::with_prefix("osmium")?;
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
        let root_key = bitcoin::util::bip32::ExtendedPrivKey::new_master(bitcoin::Network::Bitcoin, &mnemonic.to_entropy_array().0).unwrap();
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
        let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, seed.as_str())
            .expect("cannot make mnemonic").to_string();
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

