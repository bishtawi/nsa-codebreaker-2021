use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::{Read, Write};

const INPUT: &str = "resources/powershell_payload_encrypted";
const OUTPUT: &str = "resources/powershell_payload_decrypted";

#[allow(dead_code)]
pub fn decode_powershell_payload() -> std::io::Result<()> {
    let input = File::open(INPUT)?;
    let output = File::create(OUTPUT)?;
    let buf_read = BufReader::new(input);
    let mut buf_write = BufWriter::new(output);

    let mut prev = 127_u8;
    for byte in buf_read.bytes() {
        prev ^= byte?;
        buf_write.write_all(&[prev])?;
    }

    Ok(())
}
