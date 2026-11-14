//! Import a server-provided client profile and assign unused local proxy ports.
//! A free-port check cannot reserve the port after this function returns; starting
//! the proxy can still fail if another process claims a port in the meantime.
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{TcpListener, UdpSocket};
use std::path::Path;

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedProfile {
    server_address: String,
    server_port: u16,
    uuid: String,
    public_key: String,
    short_id: String,
    server_name: String,
    #[serde(default)]
    socks_port: Option<u16>,
    #[serde(default)]
    http_port: Option<u16>,
}

#[derive(Serialize)]
struct ClientProfile {
    server_address: String,
    server_port: u16,
    uuid: String,
    public_key: String,
    short_id: String,
    server_name: String,
    socks_port: u16,
    http_port: u16,
}

/// Public information for display after import. Does not contain credentials.
pub struct ImportedPorts {
    pub socks_port: u16,
    pub http_port: u16,
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253 && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn validate(profile: &ImportedProfile) -> Result<()> {
    if !valid_name(&profile.server_address) || !valid_name(&profile.server_name) || profile.server_port == 0 {
        return Err(invalid("Invalid server address, port or server name").into());
    }
    let uuid = profile.uuid.as_bytes();
    if uuid.len() != 36 || uuid.iter().enumerate().any(|(i, c)| {
        if [8, 13, 18, 23].contains(&i) { *c != b'-' } else { !c.is_ascii_hexdigit() }
    }) {
        return Err(invalid("Client ID must be a canonical UUID").into());
    }
    // Xray produces 32-byte X25519 keys in unpadded URL-safe base64 (43 characters).
    if profile.public_key.len() != 43 || !profile.public_key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
        return Err(invalid("Invalid Reality public key").into());
    }
    if profile.short_id.is_empty() || profile.short_id.len() > 16 || profile.short_id.len() % 2 != 0
        || !profile.short_id.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid("Short ID must contain 2 to 16 hexadecimal characters with an even length").into());
    }
    Ok(())
}

fn bind_socks() -> io::Result<(TcpListener, UdpSocket, u16)> {
    // Hold both listeners until the configuration is safely written. The OS can
    // assign the same number to another protocol, so check TCP and UDP together.
    for _ in 0..64 {
        let tcp = TcpListener::bind(("127.0.0.1", 0))?;
        let port = tcp.local_addr()?.port();
        if let Ok(udp) = UdpSocket::bind(("127.0.0.1", port)) { return Ok((tcp, udp, port)); }
    }
    Err(io::Error::new(io::ErrorKind::AddrInUse, "Unable to find a free SOCKS TCP and UDP port"))
}

/// Import an existing client JSON, assign separate free loopback ports, and
/// write a new client JSON. Existing files are never overwritten. Credentials
/// stay in the profile and are never printed. The caller should protect the
/// destination directory with OS access controls and run Xray's config check.
pub fn import_auto(source: &Path, destination: &Path) -> Result<ImportedPorts> {
    let metadata = fs::metadata(source)?;
    if !metadata.is_file() || metadata.len() > 65536 {
        return Err(invalid("Input profile must be a regular file smaller than 64 KiB").into());
    }
    let raw = fs::read(source)?;
    if raw.len() > 65536 { return Err(invalid("Input profile is too large").into()); }
    let input: ImportedProfile = serde_json::from_slice(&raw)?;
    validate(&input)?;
    // The input ports are deliberately ignored: they may already be in use on
    // this computer. Keep the holders alive through the write.
    let _ = (input.socks_port, input.http_port);
    let (_socks_tcp, _socks_udp, socks_port) = bind_socks()?;
    let http = TcpListener::bind(("127.0.0.1", 0))?;
    let http_port = http.local_addr()?.port();
    let output = ClientProfile {
        server_address: input.server_address,
        server_port: input.server_port,
        uuid: input.uuid,
        public_key: input.public_key,
        short_id: input.short_id,
        server_name: input.server_name,
        socks_port,
        http_port,
    };
    let bytes = serde_json::to_vec_pretty(&output)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(destination)?;
    if let Err(err) = file.write_all(&bytes).and_then(|_| file.flush()) {
        drop(file);
        let _ = fs::remove_file(destination);
        return Err(err.into());
    }
    Ok(ImportedPorts { socks_port, http_port })
}

/// Show native Windows open/save dialogs and import without exposing secrets in
/// command-line arguments. Cancelling either dialog returns `Ok(None)`.
#[cfg(windows)]
pub fn import_wizard() -> Result<Option<std::path::PathBuf>> {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::ptr;

    #[repr(C)]
    struct OpenFileNameW {
        size: u32,
        owner: *mut std::ffi::c_void,
        instance: *mut std::ffi::c_void,
        filter: *const u16,
        custom_filter: *mut u16,
        max_custom_filter: u32,
        filter_index: u32,
        file: *mut u16,
        max_file: u32,
        file_title: *mut u16,
        max_file_title: u32,
        initial_dir: *const u16,
        title: *const u16,
        flags: u32,
        file_offset: u16,
        file_extension: u16,
        default_ext: *const u16,
        custom_data: isize,
        hook: *mut std::ffi::c_void,
        template_name: *const u16,
        reserved: *mut std::ffi::c_void,
        reserved_int: u32,
        flags_ex: u32,
    }
    #[link(name = "comdlg32")]
    extern "system" {
        fn GetOpenFileNameW(ofn: *mut OpenFileNameW) -> i32;
        fn GetSaveFileNameW(ofn: *mut OpenFileNameW) -> i32;
        fn CommDlgExtendedError() -> u32;
    }
    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(owner: *mut std::ffi::c_void, text: *const u16, caption: *const u16, style: u32) -> i32;
    }
    fn wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }
    fn dialog(save: bool) -> Result<Option<std::path::PathBuf>> {
        let filter: Vec<u16> = "JSON 配置 (*.json)\0*.json\0所有文件 (*.*)\0*.*\0\0".encode_utf16().collect();
        let title = wide(if save { "保存客户端配置（请选择新文件）" } else { "选择服务器提供的客户端配置" });
        let ext = wide("json");
        let initial_dir = if save {
            let root = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "无法找到 LOCALAPPDATA，无法创建默认配置目录"))?;
            let directory = std::path::PathBuf::from(root).join("RustProxy").join("client");
            fs::create_dir_all(&directory)?;
            if !directory.is_dir() {
                return Err(invalid("默认配置目录不可用").into());
            }
            Some(directory.as_os_str().encode_wide().chain(std::iter::once(0)).collect::<Vec<u16>>())
        } else { None };
        let mut buffer = vec![0u16; 32768];
        if save {
            let default = wide("client_config.json");
            buffer[..default.len()].copy_from_slice(&default);
        }
        let mut ofn = OpenFileNameW {
            size: std::mem::size_of::<OpenFileNameW>() as u32,
            owner: ptr::null_mut(), instance: ptr::null_mut(), filter: filter.as_ptr(),
            custom_filter: ptr::null_mut(), max_custom_filter: 0, filter_index: 1,
            file: buffer.as_mut_ptr(), max_file: buffer.len() as u32,
            file_title: ptr::null_mut(), max_file_title: 0,
            initial_dir: initial_dir.as_ref().map_or(ptr::null(), |v| v.as_ptr()),
            title: title.as_ptr(), flags: 0x0008_0000 | 0x0000_0800 | 0x0000_0008 | if save { 0 } else { 0x0000_1000 },
            file_offset: 0, file_extension: 0, default_ext: ext.as_ptr(),
            custom_data: 0, hook: ptr::null_mut(), template_name: ptr::null(),
            reserved: ptr::null_mut(), reserved_int: 0, flags_ex: 0,
        };
        let ok = unsafe { if save { GetSaveFileNameW(&mut ofn) } else { GetOpenFileNameW(&mut ofn) } };
        if ok == 0 {
            let code = unsafe { CommDlgExtendedError() };
            return if code == 0 { Ok(None) } else { Err(io::Error::other(format!("Windows file dialog failed: {code:#x}")).into()) };
        }
        let len = buffer.iter().position(|&c| c == 0).ok_or_else(|| invalid("Invalid file dialog output"))?;
        Ok(Some(std::path::PathBuf::from(OsString::from_wide(&buffer[..len]))))
    }
    let source = match dialog(false)? { Some(path) => path, None => return Ok(None) };
    let destination = match dialog(true)? { Some(path) => path, None => return Ok(None) };
    let ports = import_auto(&source, &destination)?;
    let text = wide(&format!("配置导入成功。\nSOCKS5 端口：{}\nHTTP 端口：{}\n\n配置文件以明文保存连接凭据，请确保仅自己有权访问该文件和所在目录。", ports.socks_port, ports.http_port));
    let caption = wide("RustProxy 客户端");
    unsafe { MessageBoxW(ptr::null_mut(), text.as_ptr(), caption.as_ptr(), 0x40); }
    Ok(Some(destination))
}

#[cfg(not(windows))]
pub fn import_wizard() -> Result<Option<std::path::PathBuf>> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "The graphical import wizard is available on Windows only").into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn imports_with_distinct_ports_without_overwriting() {
        let dir = std::env::temp_dir().join(format!("rustproxy-client-setup-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir(&dir).unwrap();
        let source = dir.join("source.json");
        let target = dir.join("target.json");
        let data = serde_json::json!({
            "server_address": "example.com", "server_port": 443,
            "uuid": "4f4ce912-06fe-48a4-9ea6-82419339a62e",
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "short_id": "0123456789abcdef", "server_name": "example.com"
        });
        fs::write(&source, serde_json::to_vec(&data).unwrap()).unwrap();
        let ports = import_auto(&source, &target).unwrap();
        assert_ne!(ports.socks_port, ports.http_port);
        assert_ne!(ports.socks_port, 0);
        assert_ne!(ports.http_port, 0);
        let written = fs::read(&target).unwrap();
        assert!(import_auto(&source, &target).is_err());
        assert_eq!(written, fs::read(&target).unwrap());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_malformed_credentials() {
        let bad: ImportedProfile = serde_json::from_value(serde_json::json!({
            "server_address": "example.com", "server_port": 443,
            "uuid": "bad", "public_key": "bad", "short_id": "xyz", "server_name": "example.com"
        })).unwrap();
        assert!(validate(&bad).is_err());
    }
}
