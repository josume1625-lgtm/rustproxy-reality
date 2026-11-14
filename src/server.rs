use serde_json::{json, Value};
use std::error::Error;
use std::io::{self, Write};
use std::process::{Command, Stdio};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn fail(message: &str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidInput, message).into()
}

fn xray() -> std::ffi::OsString {
    if let Some(path) = std::env::var_os("XRAY_BIN") { return path; }
    let name = if cfg!(windows) { "xray.exe" } else { "xray" };
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let adjacent = parent.join(name);
            if adjacent.is_file() { return adjacent.into_os_string(); }
        }
    }
    name.into()
}

fn required_string<'a>(config: &'a Value, field: &str) -> Result<&'a str> {
    config.get(field).and_then(Value::as_str).filter(|s| !s.trim().is_empty())
        .ok_or_else(|| fail(&format!("missing or empty server field: {field}")))
}

fn string_array<'a>(config: &'a Value, field: &str) -> Result<Vec<&'a str>> {
    let values = config.get(field).and_then(Value::as_array)
        .ok_or_else(|| fail(&format!("missing server array: {field}")))?;
    if values.is_empty() { return Err(fail(&format!("server array {field} must not be empty"))); }
    values.iter().map(|v| v.as_str().filter(|s| !s.trim().is_empty())
        .ok_or_else(|| fail(&format!("server array {field} contains an empty or non-string value")))).collect()
}

fn build_config(config: &Value) -> Result<Value> {
    let port = config.get("port").and_then(Value::as_u64)
        .filter(|p| (1..=65535).contains(p)).ok_or_else(|| fail("port must be between 1 and 65535"))?;
    let listen = config.get("listen").and_then(Value::as_str).unwrap_or("0.0.0.0");
    if listen.trim().is_empty() { return Err(fail("listen must not be empty")); }
    let clients = string_array(config, "clients")?;
    for id in &clients {
        let bytes = id.as_bytes();
        if bytes.len() != 36 || bytes.iter().enumerate().any(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) { *c != b'-' } else { !c.is_ascii_hexdigit() }
        }) { return Err(fail("each client ID must be a canonical UUID")); }
    }
    let ids = string_array(config, "short_ids")?;
    for id in &ids {
        if id.len() > 16 || id.len() % 2 != 0 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(fail("short IDs must contain 2 to 16 hexadecimal characters, with even length"));
        }
    }
    let names = string_array(config, "server_names")?;
    let dest = required_string(config, "dest")?;
    let key = required_string(config, "private_key")?;
    Ok(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": listen, "port": port, "protocol": "vless",
            "settings": {"clients": clients.iter().map(|id| json!({"id": id, "flow": "xtls-rprx-vision"})).collect::<Vec<_>>(), "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "show": false, "dest": dest, "serverNames": names, "privateKey": key, "shortIds": ids
            }}
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}]
    }))
}

fn invoke(config: &[u8], test: bool) -> Result<()> {
    let mut command = Command::new(xray());
    command.args(["run", "-config", "stdin:"]);
    if test { command.arg("-test"); }
    let mut child = command.stdin(Stdio::piped()).spawn()?;
    let write_result = child.stdin.take().ok_or_else(|| fail("failed to open Xray stdin"))?.write_all(config);
    if let Err(e) = write_result { let _ = child.kill(); let _ = child.wait(); return Err(e.into()); }
    let status = child.wait()?;
    if !status.success() { return Err(fail(&format!("Xray exited with {status}"))); }
    Ok(())
}

fn keygen() -> Result<()> {
    let status = Command::new(xray()).arg("x25519").status()?;
    if !status.success() { return Err(fail("Xray x25519 failed")); }
    let output = Command::new(xray()).arg("uuid").output()?;
    if !output.status.success() { return Err(fail("Xray uuid failed")); }
    let uuid = String::from_utf8(output.stdout)?;
    let digits: String = uuid.trim().chars().filter(|c| *c != '-').collect();
    if digits.len() != 32 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(fail("unexpected output from Xray uuid"));
    }
    println!("ShortId: {}", &digits[..16]);
    let client_uuid = Command::new(xray()).arg("uuid").output()?;
    if !client_uuid.status.success() { return Err(fail("Xray uuid failed")); }
    println!("Client UUID: {}", String::from_utf8(client_uuid.stdout)?.trim());
    Ok(())
}

pub fn run(args: &[String]) -> Result<()> {
    match args {
        [command] if command == "keygen" => keygen(),
        [command, path] if command == "run" => {
            let config: Value = serde_json::from_slice(&std::fs::read(path)?)?;
            let encoded = serde_json::to_vec(&build_config(&config)?)?;
            invoke(&encoded, true)?;
            invoke(&encoded, false)
        }
        _ => Err(fail("usage: server keygen | server run <config.json>")),
    }
}
