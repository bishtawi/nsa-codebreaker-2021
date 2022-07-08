#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

mod shared;
mod task03;
mod task08;
mod task09;
mod task10;

fn main() {
    task03::decode_powershell_payload().expect("Unable to decode powershell payload");
    task08::decrypt_payloads().expect("Unable to decrypt payloads");
    task08::match_ips().expect("Unable to parse ip and/or ranges");
    task09::leak_uuids().expect("Failed to leak uuids");
    task10::leak_server_private_key().expect("Failed to leak private key");
    task10::http_exploit().expect("Failed to exploit http server");
}
