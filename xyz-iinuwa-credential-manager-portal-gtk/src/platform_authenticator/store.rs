use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;

use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::rand::{self, SecureRandom};

use crate::webauthn::{CredentialDescriptor, Error, RelyingParty};
static mut CRED_DIR: String = String::new();

pub(crate) fn initialize() {
    let cred_dir = get_cred_dir();
    fs::create_dir_all(cred_dir).unwrap();
}

pub(crate) async fn store_secret<'a>(
    origins: &'a [&str],
    display_name: &'a str,
    user_display_name: &'a str,
    content_type: &'a str,
    metadata: Option<HashMap<&'a str, &'a str>>,
    contents: &'a [u8],
) -> Result<String, Error> {
    let id = {
        let rng = rand::SystemRandom::new();
        let mut buf = [0; 32];
        rng.fill(&mut buf).map_err(|_| Error::Unknown)?;
        URL_SAFE_NO_PAD.encode(buf)
    };
    /*
    let service = oo7::dbus::Service::new(oo7::dbus::Algorithm::Encrypted).await?;
    let collection = service.with_label("WEBAUTHN").await?.unwrap();
    collection.create_item(
        "Item Label",
        HashMap::from([(
            "cred_id", credential_source.id,
            "version", 1
        )]),
        credential_source.key_pair,
        true,
        "application/octet-stream"
    ).await?;
    */
    let cred_path = {
        let mut d = get_cred_dir();
        d.push(&id);
        d
    };
    let mut cred_file = File::create(cred_path).unwrap();
    cred_file.write_all(b"Origin: ").unwrap();
    for (i, origin) in origins.iter().enumerate() {
        cred_file.write_all(origin.as_bytes()).unwrap();
        if i < origins.len() - 1 {
            cred_file.write_all(b"; ").unwrap();
        } else {
            cred_file.write_all(b"\r\n").unwrap();
        }
    }
    cred_file
        .write_fmt(format_args!("Name: {display_name}\r\n"))
        .unwrap();
    cred_file
        .write_fmt(format_args!("User-Display-Name: {user_display_name}\r\n"))
        .unwrap();
    cred_file
        .write_fmt(format_args!("Content-Type: {content_type}\r\n"))
        .unwrap();
    if let Some(metadata) = metadata {
        for (key, value) in metadata.iter() {
            if key.contains(':') {
                return Err(Error::Unknown);
            }
            cred_file
                .write_fmt(format_args!("{key}: {value}\r\n"))
                .unwrap();
        }
    }

    cred_file.write_all(b"\r\n").unwrap();

    cred_file.write_all(contents).unwrap();
    Ok(id)
}

pub(crate) async fn lookup_password_credentials(origin: &str) -> Option<(String, String)> {
    let cred_path = get_cred_dir();
    'file: for cred_file in cred_path.read_dir().expect("credential directory to exist") {
        let credential = match File::open(cred_file.unwrap().path()) {
            Ok(mut cred_file) => {
                let mut cred = String::new();
                cred_file.read_to_string(&mut cred).unwrap();
                let mut password: Option<String> = None;
                let mut id: Option<String> = None;
                let mut origin_matches: bool = false;
                let mut content_type = None;

                let boundary = cred.find("\r\n\r\n").unwrap();
                let headers = cred[..boundary].split("\r\n");
                for header in headers {
                    if let Some((key, value)) = header.split_once(": ") {
                        if key == "Origin" {
                            if !value.split("; ").any(|o| o == origin) {
                                continue 'file;
                            } else {
                                origin_matches = true;
                            }
                        } else if key == "Content-Type" {
                            content_type = Some(value);
                        }
                    } else {
                        break;
                    }
                }
                if origin_matches && content_type.is_some_and(|ct| ct == "secret/password") {
                    let body = &cred[boundary + 4..];
                    for pair in body.split('&') {
                        let decoded = pair.replace("%26", "&").replace("%25", "%");
                        if let Some((key, value)) = decoded.split_once('=') {
                            if key == "id" {
                                id = Some(value.to_string())
                            } else if key == "password" {
                                password = Some(value.to_string())
                            }
                        }
                    }
                    id.zip(password)
                } else {
                    None
                }
            }
            _ => None,
        };
        if credential.is_some() {
            return credential;
        }
    }
    None
}

fn get_cred_dir() -> PathBuf {
    let data_home = if let Ok(data_home) = env::var("XDG_DATA_HOME") {
        PathBuf::from_str(&data_home).unwrap()
    } else {
        PathBuf::from_str(&env::var("HOME").expect("$HOME not set"))
            .unwrap()
            .join(".local/share")
    };
    fs::create_dir_all(&data_home).unwrap();
    data_home.join("xyz.iinuwa.CredentialManager/credentials")
}
