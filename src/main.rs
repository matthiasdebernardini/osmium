use crate::bitcoin::secp256k1::Secp256k1;
use crate::bitcoin::util::bip32::ExtendedPrivKey;
use anyhow::{Result};
use bip39::*;
use bip85::*;
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
    path::Path,
};



fn main() -> Result<(), Box<dyn Error>> {
    let path = env::var("HOME")?;
    // TODO: make home dir
    let path = Path::new(path.as_str());

    if let true = path.is_dir() {
        let path = path.to_str().expect("Path provided must be valid UTF-8");
        panic!("{path} already exists")
    };

    match fs::create_dir(path) {
        Ok(_) => (),
        Err(e) => panic!("Error creating new folder: {e}"),
    };
    let _path = path.to_str();
    let path = format!("/.config/osmium");
    let _matches = Command::new("osmium")
        .version("0.1.5")
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
        let path = format!("{path}/mnemonic.backup");
        let f = File::create(path).expect("Unable to create file");
        let mut f = BufWriter::new(f);
        f.write_all(mnemonic.as_bytes())
            .expect("Unable to write data");
    }
    if make_new {
        // avoids accidentaly using these keys in wallet software
        let network = bitcoin::Network::Regtest;
        let path = format!("{path}/mnemonic.backup");
        let contents = fs::read_to_string(path)
            .expect("Something went wrong when reading the mnemonic backup");
        let seed = bip39::Mnemonic::parse_in_normalized(Language::English, contents.as_str())?
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
    let xprv = to_xprv(&secp, &root, index as u32).expect("Could not derive ExtendedPrivKey");
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
