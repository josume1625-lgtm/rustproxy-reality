use serde::Deserialize;
use serde_json::{json, Value};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientConfig {
    server_address: String,
    server_port: u16,
    uuid: String,
    public_key: String,
    short_id: String,
    server_name: String,
    socks_port: u16,
    http_port: u16,
}

fn invalid(message: &str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_owned()).into()
}

fn read_config(path: &str) -> Result<ClientConfig> {
    let bytes = std::fs::read(path)?;
    parse_config(&bytes)
}

fn parse_config(bytes: &[u8]) -> Result<ClientConfig> {
    let config: ClientConfig = serde_json::from_slice(bytes)?;
    if config.server_address.trim().is_empty()
        || config.server_name.trim().is_empty()
        || config.uuid.trim().is_empty()
        || config.public_key.trim().is_empty()
    {
        return Err(invalid("server_address, server_name, uuid and public_key must not be empty"));
    }
    if config.server_port == 0 || config.socks_port == 0 || config.http_port == 0 {
        return Err(invalid("ports must be in the range 1..=65535"));
    }
    if config.socks_port == config.http_port {
        return Err(invalid("socks_port and http_port must be different"));
    }
    if config.short_id.len() > 16
        || config.short_id.len() % 2 != 0
        || !config.short_id.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid("short_id must contain an even number of hexadecimal characters (at most 16)"));
    }
    Ok(config)
}

fn xray_config(config: &ClientConfig) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"listen": "127.0.0.1", "port": config.socks_port, "protocol": "socks", "settings": {"udp": true}},
            {"listen": "127.0.0.1", "port": config.http_port, "protocol": "http"}
        ],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "address": config.server_address,
                "port": config.server_port,
                "id": config.uuid,
                "encryption": "none",
                "flow": "xtls-rprx-vision"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "fingerprint": "chrome",
                    "serverName": config.server_name,
                    "publicKey": config.public_key,
                    "shortId": config.short_id,
                    "spiderX": "/"
                }
            }
        }]
    })
}

fn xray_path() -> PathBuf {
    if let Some(path) = std::env::var_os("XRAY_BIN") {
        return PathBuf::from(path);
    }
    let name = if cfg!(windows) { "xray.exe" } else { "xray" };
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let adjacent = dir.join(name);
            if adjacent.is_file() {
                return adjacent;
            }
        }
    }
    Path::new(name).to_owned()
}

fn execute_xray(config: &ClientConfig, test: bool) -> Result<()> {
    let mut command = Command::new(xray_path());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    command.arg("run");
    if test {
        command.arg("-test");
    }
    // Xray consumes stdin to EOF before starting, so no credential-bearing
    // temporary configuration file is ever created.
    command.args(["-config", "stdin:"]).stdin(Stdio::piped());
    let mut child = command.spawn().map_err(|e| {
        io::Error::new(e.kind(), format!("failed to start Xray (set XRAY_BIN to its executable): {e}"))
    })?;
    let write_result = (|| -> Result<()> {
        let mut stdin = child.stdin.take().ok_or_else(|| invalid("Xray stdin unavailable"))?;
        serde_json::to_writer(&mut stdin, &xray_config(config))?;
        stdin.flush()?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(invalid(&format!("Xray exited with status {status}")));
    }
    Ok(())
}

fn tcp_ping(config: &ClientConfig) -> Result<()> {
    let addresses: Vec<_> = (config.server_address.as_str(), config.server_port)
        .to_socket_addrs()?
        .collect();
    if addresses.is_empty() {
        return Err(invalid("server address resolved to no IP addresses"));
    }
    let mut last_error = None;
    for address in addresses {
        let start = Instant::now();
        match TcpStream::connect_timeout(&address, Duration::from_secs(5)) {
            Ok(_) => {
                println!("TCP connection to {address}: {:.2} ms", start.elapsed().as_secs_f64() * 1000.0);
                return Ok(());
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.expect("nonempty addresses").into())
}

fn reality_test(port_text: &str, url: &str) -> Result<()> {
    let port = port_text.parse::<u16>().ok().filter(|p| *p != 0)
        .ok_or_else(|| invalid("HTTP proxy port must be in the range 1..=65535"))?;
    let rest = url.strip_prefix("https://").ok_or_else(|| invalid("test URL must start with https://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') || authority.contains('\\')
        || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid("test URL must contain a valid HTTPS host and no credentials or whitespace"));
    }
    let proxy = format!("http://127.0.0.1:{port}");
    let start = Instant::now();
    let result = Command::new(if cfg!(windows) { "curl.exe" } else { "curl" })
        .args(["--disable", "--silent", "--show-error", "--fail", "--max-time", "30",
            "--connect-timeout", "10", "--noproxy", "", "--proxy", &proxy,
            "--output", if cfg!(windows) { "NUL" } else { "/dev/null" }, "--", url])
        .status()?;
    if !result.success() {
        return Err(invalid(&format!("HTTPS request through the local proxy failed: curl exited with {result}")));
    }
    println!("HTTPS through local HTTP proxy: {:.2} ms", start.elapsed().as_secs_f64() * 1000.0);
    Ok(())
}

// Profile names are deliberately restricted to one portable path component.
fn profile_path(directory: &str, name: &str) -> Result<PathBuf> {
    if name.is_empty() || name.len() > 64 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
        return Err(invalid("profile name must contain 1–64 ASCII letters, digits, underscores or hyphens"));
    }
    // Windows reserves these device names even when an extension is present.
    let upper = name.to_ascii_uppercase();
    if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9" | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9") {
        return Err(invalid("profile name is reserved on Windows"));
    }
    Ok(Path::new(directory).join(format!("{name}.json")))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.flush()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error.into());
    }
    Ok(())
}

fn list_profiles(directory: &str) -> Result<()> {
    let mut names = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() { continue; }
        let filename = entry.file_name();
        if let Some(filename) = filename.to_str() {
            if let Some(name) = filename.strip_suffix(".json") {
                if profile_path(directory, name).is_ok() {
                    names.push(name.to_owned());
                }
            }
        }
    }
    names.sort();
    for name in names { println!("{name}"); }
    Ok(())
}

fn regular_profile_path(directory: &str, name: &str) -> Result<PathBuf> {
    let path = profile_path(directory, name)?;
    if !fs::symlink_metadata(&path)?.file_type().is_file() {
        return Err(invalid("profile must be a regular file"));
    }
    Ok(path)
}

pub fn run(args: &[String]) -> Result<()> {
    match args {
        [command, path] if command == "run" || command == "check" || command == "tcp-ping" => {
            let config = read_config(path)?;
            match command.as_str() {
                "run" => execute_xray(&config, false),
                "check" => execute_xray(&config, true),
                _ => tcp_ping(&config),
            }
        }
        [command, directory] if command == "list" => list_profiles(directory),
        [command, port, url] if command == "reality-test" => reality_test(port, url),
        [command, source, directory, name] if command == "import" => {
            let bytes = fs::read(source)?;
            let _ = parse_config(&bytes)?;
            let path = profile_path(directory, name)?;
            fs::create_dir_all(directory)?;
            write_new(&path, &bytes)
        }
        [command, directory, name, destination] if command == "export" => {
            let path = regular_profile_path(directory, name)?;
            let bytes = fs::read(path)?;
            let _ = parse_config(&bytes)?;
            write_new(Path::new(destination), &bytes)
        }
        [command, directory, name] if command == "delete" => {
            fs::remove_file(regular_profile_path(directory, name)?)?;
            Ok(())
        }
        _ => Err(invalid("usage: client <run|check|tcp-ping> <config.json> | reality-test <http-port> <https-url> | list <directory> | import <source.json> <directory> <name> | export <directory> <name> <destination.json> | delete <directory> <name>")),
    }
}
