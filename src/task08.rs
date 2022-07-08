use crate::shared;
use anyhow::{anyhow, Result};
use cidr::Ipv4Cidr;
use itertools::Itertools;
use rayon::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::str::FromStr;
use xsalsa20poly1305::aead::NewAead;
use xsalsa20poly1305::XSalsa20Poly1305;

// Search constraints
const TIME_WINDOW: (i32, i32) = (10, 0); // seconds
const MAX_VERSION: i32 = 9; // inclusive

// External resources
const PAYLOADS: &str = "resources/task8_encrypted_payloads";
const LOGINS: &str = "resources/logins.json";
const USERNAMES: &str = "resources/usernames.txt";
const COMMON_NAMES: &str = "resources/common_names.txt";
const IP_RANGES: &str = "resources/ip_ranges.txt";
const IPS: &str = "resources/task8_ips.txt";

#[allow(dead_code)]
pub fn match_ips() -> Result<()> {
    let mut ranges: Vec<Ipv4Cidr> = Vec::new();

    let file = File::open(IP_RANGES)?;
    let buf = BufReader::new(file);
    for line in buf.lines() {
        ranges.push(Ipv4Cidr::from_str(&line?)?);
    }

    let file = File::open(IPS)?;
    let buf = BufReader::new(file);
    for line in buf.lines() {
        let ip = Ipv4Addr::from_str(&line?)?;
        let found = ranges.iter().any(|&cidr| cidr.contains(&ip));
        println!("{}: {}", ip, found);
    }

    Ok(())
}

#[allow(dead_code)]
pub fn decrypt_payloads() -> Result<()> {
    let payloads = get_payloads(PAYLOADS)?;
    let usernames = get_usernames(LOGINS, USERNAMES, COMMON_NAMES)?;

    payloads.into_par_iter().for_each(|(payload, timestamp)| {
        match decrypt_payload(&usernames, &payload, timestamp) {
            Ok((secret, plaintext)) => {
                let hexstring = hex::encode(plaintext);
                println!(
                    "Decrypted '{} ...' using secret '{}': {}",
                    &payload[..10],
                    secret,
                    hexstring
                );
                if !hexstring.starts_with(shared::MAGIC_START)
                    || !hexstring.ends_with(shared::MAGIC_END)
                {
                    println!("WARNING: Magic bytes do NOT match!!!");
                }
            }
            Err(e) => {
                println!(
                    "ERROR: Unable to decrypt '{} ...' ({} bytes) - {}",
                    &payload[..10],
                    payload.len() / 2,
                    e,
                );
            }
        }
    });

    Ok(())
}

fn get_payloads(path: &str) -> Result<Vec<(String, i32)>> {
    let mut entries: Vec<(String, i32)> = Vec::new();

    let file = File::open(path)?;
    let buf = BufReader::new(file);
    for (payload, timestamp) in buf.lines().tuples() {
        let payload = payload?;
        let timestamp = timestamp?.parse::<i32>()?;
        entries.push((payload, timestamp));
    }

    Ok(entries)
}

fn get_usernames(
    logins_path: &str,
    usernames_path: &str,
    common_names_path: &str,
) -> Result<Vec<String>> {
    let mut usernames = HashSet::new();

    let attribute = "PayloadData1";
    let prefix = "Target: ";
    let file = File::open(logins_path)?;
    let buf = BufReader::new(file);
    for line in buf.lines() {
        let line = line?;
        let json: Value = serde_json::from_str(&line)?;
        match &json[attribute] {
            Value::String(data) => {
                assert!(data.starts_with(prefix));

                // various variations of the username
                usernames.insert(data[prefix.len()..].trim().to_lowercase());
                usernames.insert(data[data.find('\\').unwrap() + 1..].trim().to_lowercase());
                usernames.insert(
                    data[prefix.len()..data.find('@').unwrap_or(data.len())]
                        .trim()
                        .to_lowercase(),
                );
                let username = data
                    [data.find('\\').unwrap() + 1..data.find('@').unwrap_or(data.len())]
                    .trim()
                    .to_lowercase();
                if let Some(index) = username.find('.') {
                    usernames.insert(username[..index].to_string());
                    usernames.insert(username[index + 1..].to_string());
                }
                usernames.insert(username);
            }
            x => {
                return Err(anyhow!("Unexpected JSON datatype {}", x));
            }
        }
    }

    let file = File::open(usernames_path)?;
    let buf = BufReader::new(file);
    for line in buf.lines() {
        let username = line?.trim().to_lowercase();
        if let Some(index) = username.find('.') {
            usernames.insert(username[..index].to_string());
            usernames.insert(username[index + 1..].to_string());
        }
        usernames.insert(username);
    }

    let file = File::open(common_names_path)?;
    let buf = BufReader::new(file);
    for line in buf.lines() {
        usernames.insert(line?.trim().to_lowercase());
    }

    Ok(usernames.into_iter().collect())
}

fn decrypt_payload(
    usernames: &[String],
    payload_hexstring: &str,
    timestamp: i32,
) -> Result<(String, Vec<u8>)> {
    let payload_rawbytes = hex::decode(payload_hexstring)?;
    let (nonce, ciphertext) = shared::parse_payload(&payload_rawbytes)?;
    iterate_usernames(usernames, nonce, ciphertext, timestamp)
}

fn iterate_usernames(
    usernames: &[String],
    nonce: &[u8],
    ciphertext: &[u8],
    timestamp: i32,
) -> Result<(String, Vec<u8>)> {
    for username in usernames {
        let res = iterate_timestamps(nonce, ciphertext, username, timestamp);
        if res.is_ok() {
            return res;
        }
    }

    Err(anyhow!("Payload failed to be decrypted"))
}

fn iterate_timestamps(
    nonce: &[u8],
    ciphertext: &[u8],
    username: &str,
    timestamp: i32,
) -> Result<(String, Vec<u8>)> {
    for t in timestamp - TIME_WINDOW.0..=timestamp + TIME_WINDOW.1 {
        let res = iterate_versions(nonce, ciphertext, username, t);
        if res.is_ok() {
            return res;
        }
    }

    Err(anyhow!("Payload failed to be decrypted"))
}

fn iterate_versions(
    nonce: &[u8],
    ciphertext: &[u8],
    username: &str,
    timestamp: i32,
) -> Result<(String, Vec<u8>)> {
    for a in 0..=MAX_VERSION {
        for b in 0..=MAX_VERSION {
            for c in 0..=MAX_VERSION {
                for d in 0..=MAX_VERSION {
                    let version = format!("{}.{}.{}.{}", a, b, c, d);
                    let res = attempt_decrypt(nonce, ciphertext, username, &version, timestamp);
                    if res.is_ok() {
                        return res;
                    }
                }
            }
        }
    }

    Err(anyhow!("Payload failed to be decrypted"))
}

fn attempt_decrypt(
    nonce: &[u8],
    ciphertext: &[u8],
    username: &str,
    version: &str,
    timestamp: i32,
) -> Result<(String, Vec<u8>)> {
    let secret = format!("{}+{}+{}", username, version, timestamp);
    let mut hasher = Sha256::new();
    hasher.update(&secret);
    let key = hasher.finalize();
    let cipher = XSalsa20Poly1305::new(&key);

    match shared::decrypt(&cipher, nonce, ciphertext) {
        Ok(plaintext) => Ok((secret, plaintext)),
        Err(e) => Err(e),
    }
}
