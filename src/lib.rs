use std::{env, fs, path::Path};

use anyhow::Context;
use config::Config;
use thiserror::Error;
use xdg::BaseDirectories;
struct User {
    config: String,
    registered: bool,
    seed: String,
    pubkey: String,
}

trait New {
    fn configure(&self) -> Result<Config, NewUserError>;
    fn get_pubkey(&self) -> String;
    fn make_seed(&self) -> String;
    fn new() -> Self;
    fn register(&self) -> bool;
}

#[derive(Error, Debug)]
pub enum NewUserError {
    #[error("config error")]
    ConfigurationError(#[from] std::env::VarError),
    #[error("unknown new user error")]
    Unknown,
}

impl From<()> for NewUserError {
    fn from(_: ()) -> Self {
        NewUserError::ConfigurationError(env::VarError::NotPresent)
    }
}

impl New for User {
    fn configure(&self) -> Result<Config, NewUserError> {
        let path: String = env::var("HOME").map_err(|e| {
            NewUserError::ConfigurationError(e);
        })?;
        let xdg_dirs = BaseDirectories::with_prefix("myapp").unwrap();
        println!("path {path:?} xdg {xdg_dirs:?}");
        //   .context("could not read file").into()?;
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
        let path = path.to_str();
        let path = format!("/.config/osmium");
        unimplemented!()
    }

    fn make_seed(&self) -> String {
        todo!()
    }

    fn register(&self) -> bool {
        todo!()
    }

    fn get_pubkey(&self) -> String {
        todo!()
    }

    fn new() -> Self {
        User {
            config: "".to_string(),
            registered: true,
            seed: "".to_string(),
            pubkey: "".to_string(),
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
        assert_eq!(User::make_seed(&user), "");
    }
    #[test]
    fn configure() {
        let user = User::new();
        User::configure(&user);
        panic!()
    }
}
