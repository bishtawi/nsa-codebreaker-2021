use anyhow::{anyhow, Result};
use rand::rngs::OsRng;
use std::io::{Read, Write};
use std::net::TcpStream;
use xsalsa20poly1305::aead::{generic_array::GenericArray, Aead, NewAead};
use xsalsa20poly1305::XSalsa20Poly1305;

// Reversed engineered the server communication protocol:

// Server commands:
// 0001: register (returns resp code 0033 so not implemented)
// 0002: init session
// 0003: pwd (returned "/tmp/endpoints/b82dc9a0-e269-4ced-a603-4849ddcc1e09/tasking")
// 0004: ls (returns list of files in a directory)
// 0005: cat (returns contents of file but truncated to some max length)
// 0006: upload file
// 0007: fin session

// Resp codes:
// 0000: ok
// 0011: cmd missing from request
// 0022: invalid cmd
// 0033: cmd not implemented
// 0044: missing param(s)

// Server info
pub const SERVER: &str = "54.145.229.33"; // ssh -i resources/server_private_key lpuser@54.145.229.33
const PORT: i32 = 6666;

// Dynamically generated crypto data grabbed from gdb
const SETUP: &str = "54b646f59761077c8b03d64b46794f07e5a2f736a5a547813c8bda11c2bed112a5705b17c1d837015855e4056337077dcf448df6fd1d09942d75e4af5316f4bb61650d53a32148e9c8876b95881ed28274f8df62de1408715d66322fcbd4fe600f6ec957e29e302c0cd3ab9cb27157bf946fb4ede66fbbc75ab376240fb4cce5884b9453219fa2a34071adaacade194d5ba58bd7356b6e80e69496e6079746587746935e1409ea68b7594c";
const SESSION_KEY: &str = "1173cd2f15b5169e8376b8e82f6177b3a738c0993bf552abf44faa0a82422bd1";

// Our "random" constants
const LEN_HEADER_BYTES: [u8; 2] = [0xde, 0xad];
const LEN_HEADER_VAL: usize = 57005; // Value of LEN_HEADER_BYTES (0xdead == 57005)
pub const UUID: &str = "b82dc9a0e2694ceda6034849ddcc1e09";

// Message tokens
pub const MAGIC_START: &str = "1e6818b7";
pub const MAGIC_END: &str = "eeab6633";
pub const COMMAND_UNKNOWN1: &str = "0001";
pub const COMMAND_INIT: &str = "0002";
pub const COMMAND_PWD: &str = "0003";
pub const COMMAND_LS: &str = "0004";
pub const COMMAND_CAT: &str = "0005";
pub const COMMAND_UPLOAD: &str = "0006";
pub const COMMAND_FIN: &str = "0007";
pub const PARAM_UUID: &str = "2C08";
pub const UUID_LEN: &str = "0010";
pub const PARAM_DIRNAME: &str = "2C14";
pub const PARAM_FILENAME: &str = "2C1C";
const PARAM_CMD: &str = "2C00";
const CMD_LEN: &str = "0002";

// Message lengths
pub const NONCE_LEN: usize = 0x18; // bytes
pub const HEADER_LEN: usize = 4; // bytes

// Response message lengths
const FULL_HEADER_LEN: usize = 8;
const FULL_FOOTER_LEN: usize = 5;

const LEN_OFFSET: usize = 0x10000;

pub fn connect() -> Result<(xsalsa20poly1305::XSalsa20Poly1305, TcpStream)> {
    let session_key = hex::decode(SESSION_KEY)?;
    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(&session_key));

    println!("Attempting connection...");
    let mut stream = TcpStream::connect(format!("{}:{}", SERVER, PORT))?;
    println!("Connected!");

    // Initial crypt negotiation
    stream.write_all(&hex::decode(SETUP)?)?;

    Ok((cipher, stream))
}

pub fn send_cmd(
    cipher: &xsalsa20poly1305::XSalsa20Poly1305,
    stream: &mut TcpStream,
    cmd: &str,
    extra: &str,
) -> Result<()> {
    println!("Command: {}", cmd);
    let nonce = xsalsa20poly1305::generate_nonce(&mut OsRng::default());
    assert!(nonce.len() == NONCE_LEN);
    let plaintext = hex::decode(format!(
        "{}{}{}{}{}{}",
        MAGIC_START, PARAM_CMD, CMD_LEN, cmd, extra, MAGIC_END
    ))?;
    let mut ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();
    let mut payload: Vec<u8> = Vec::new(); // 4 byte length_header + 0x18 byte random nonce + ciphertext
    payload.extend_from_slice(&LEN_HEADER_BYTES);
    payload.extend_from_slice(
        &(nonce.len() + ciphertext.len() + LEN_OFFSET - LEN_HEADER_VAL).to_be_bytes()[6..],
    );
    payload.extend_from_slice(&nonce);
    payload.append(&mut ciphertext);
    stream.write_all(&payload)?;

    Ok(())
}

pub fn get_responses(
    cipher: &xsalsa20poly1305::XSalsa20Poly1305,
    stream: &mut TcpStream,
) -> Result<Vec<Vec<u8>>> {
    // Get resp
    let mut resp: Vec<u8> = Vec::new();
    println!("Reading response...");
    stream.read_to_end(&mut resp)?;
    println!("Response finish!");

    // Decode response(s)
    let mut plaintexts: Vec<Vec<u8>> = Vec::new();
    let mut index = 0;
    while index < resp.len() {
        let (nonce, ciphertext) = parse_payload(&resp[index..])?;
        let plaintext = decrypt(cipher, nonce, ciphertext)?;
        plaintexts.push(plaintext);
        index += NONCE_LEN + HEADER_LEN + ciphertext.len();
    }

    Ok(plaintexts)
}

pub fn parse_payload(payload: &[u8]) -> Result<(&[u8], &[u8])> {
    let header = hex::encode(&payload[0..HEADER_LEN]);
    let length = usize::from_str_radix(&header[4..], 16)?
        + usize::from_str_radix(&header[..4], 16)?
        - LEN_OFFSET
        - NONCE_LEN;
    let nonce = &payload[HEADER_LEN..NONCE_LEN + HEADER_LEN];
    assert_eq!(nonce.len(), NONCE_LEN);
    let ciphertext = &payload[NONCE_LEN + HEADER_LEN..NONCE_LEN + HEADER_LEN + length];
    if ciphertext.len() != length {
        return Err(anyhow!(
            "Ciphertext is {} bytes but header said {} bytes ({})",
            ciphertext.len(),
            length,
            header
        ));
    }

    Ok((nonce, ciphertext))
}

pub fn decrypt(
    cipher: &xsalsa20poly1305::XSalsa20Poly1305,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    match cipher.decrypt(GenericArray::from_slice(nonce), ciphertext) {
        Ok(plaintext) => Ok(plaintext),
        Err(e) => Err(anyhow!("{}: Failed to decrypt", e)),
    }
}

pub fn get_message_body(payload: &[u8]) -> &[u8] {
    &payload[FULL_HEADER_LEN..payload.len() - FULL_FOOTER_LEN]
}
