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
    import_profile(source, destination, None)
}

/// Import a profile using the address and port of the user's tunnel endpoint.
/// The source profile remains unchanged and the destination is never overwritten.
pub fn import_endpoint(source: &Path, destination: &Path, address: &str, port: u16) -> Result<ImportedPorts> {
    validate_endpoint(address, port)?;
    import_profile(source, destination, Some((address, port)))
}

fn validate_endpoint(address: &str, port: u16) -> Result<()> {
    let valid_address = address.parse::<std::net::IpAddr>().is_ok() ||
        (address.len() <= 253 && !address.is_empty() && address.split('.').all(|label| {
            !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-') &&
                label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        }));
    if !valid_address || port == 0 { return Err(invalid("Invalid tunnel address or port").into()); }
    Ok(())
}

fn import_profile(source: &Path, destination: &Path, endpoint: Option<(&str, u16)>) -> Result<ImportedPorts> {
    let metadata = fs::metadata(source)?;
    if !metadata.is_file() || metadata.len() > 65536 {
        return Err(invalid("Input profile must be a regular file smaller than 64 KiB").into());
    }
    let raw = fs::read(source)?;
    if raw.len() > 65536 { return Err(invalid("Input profile is too large").into()); }
    import_bytes(&raw, destination, endpoint)
}

fn import_bytes(raw: &[u8], destination: &Path, endpoint: Option<(&str, u16)>) -> Result<ImportedPorts> {
    if raw.len() > 65536 { return Err(invalid("Input profile is too large").into()); }
    let mut value: serde_json::Value = serde_json::from_slice(raw)?;
    if let Some((address, port)) = endpoint {
        validate_endpoint(address, port)?;
        let fields = value.as_object_mut().ok_or_else(|| invalid("Invalid client credentials"))?;
        fields.insert("server_address".into(), address.into());
        fields.insert("server_port".into(), port.into());
    }
    let input: ImportedProfile = serde_json::from_value(value)?;
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

#[cfg(windows)]
fn tunnel_endpoint_dialog() -> Result<Option<(String, u16)>> {
    use std::os::windows::process::CommandExt;
    // Static script only: entered values return as JSON, never as shell source.
    let script = r#"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$form = New-Object System.Windows.Forms.Form
$form.Text = 'RustProxy 连接设置'
$form.ClientSize = New-Object System.Drawing.Size(500, 220)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$label = New-Object System.Windows.Forms.Label
$label.Text = '内网穿透提供的公网 IP 或域名'; $label.Left = 20; $label.Top = 15; $label.Width = 450
$form.Controls.Add($label)
$address = New-Object System.Windows.Forms.TextBox
$address.Left = 20; $address.Top = 40; $address.Width = 460
$form.Controls.Add($address)
$label2 = New-Object System.Windows.Forms.Label
$label2.Text = '内网穿透提供的公网端口'; $label2.Left = 20; $label2.Top = 80; $label2.Width = 450
$form.Controls.Add($label2)
$port = New-Object System.Windows.Forms.TextBox
$port.Left = 20; $port.Top = 105; $port.Width = 160
$form.Controls.Add($port)
$ok = New-Object System.Windows.Forms.Button
$ok.Text = '连接'; $ok.Left = 290; $ok.Top = 165; $ok.Width = 90
$ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
$cancel = New-Object System.Windows.Forms.Button
$cancel.Text = '取消'; $cancel.Left = 390; $cancel.Top = 165; $cancel.Width = 90
$cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.Controls.Add($ok); $form.Controls.Add($cancel)
$form.AcceptButton = $ok; $form.CancelButton = $cancel
$form.Add_FormClosing({
  param($sender, $event)
  if ($form.DialogResult -ne [System.Windows.Forms.DialogResult]::OK) { return }
  $value = 0
  if ([string]::IsNullOrWhiteSpace($address.Text) -or -not [int]::TryParse($port.Text, [ref]$value) -or $value -lt 1 -or $value -gt 65535) {
    [System.Windows.Forms.MessageBox]::Show('请填写公网 IP 或域名及 1 到 65535 的端口。', 'RustProxy') | Out-Null
    $event.Cancel = $true
  }
})
if ($form.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
  [Console]::Out.Write('{"cancelled":true}')
} else {
  [Console]::Out.Write((@{ cancelled = $false; address = $address.Text; port = $port.Text } | ConvertTo-Json -Compress))
}
$form.Dispose()
"#;
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let a = chunk[0]; let b = *chunk.get(1).unwrap_or(&0); let c = *chunk.get(2).unwrap_or(&0);
        encoded.push(alphabet[(a >> 2) as usize] as char);
        encoded.push(alphabet[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        encoded.push(if chunk.len() > 1 { alphabet[(((b & 15) << 2) | (c >> 6)) as usize] as char } else { '=' });
        encoded.push(if chunk.len() > 2 { alphabet[(c & 63) as usize] as char } else { '=' });
    }
    let preferred = std::env::var_os("ProgramFiles").map(std::path::PathBuf::from)
        .map(|p| p.join("PowerShell").join("7").join("pwsh.exe"));
    let executable = preferred.filter(|p| p.is_file()).unwrap_or_else(|| {
        std::env::var_os("SystemRoot").map(std::path::PathBuf::from).unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"))
            .join("System32").join("WindowsPowerShell").join("v1.0").join("powershell.exe")
    });
    let output = std::process::Command::new(executable)
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-STA", "-EncodedCommand", &encoded])
        .creation_flags(0x08000000).output()?;
    if !output.status.success() { return Err(io::Error::other("无法显示公网连接设置窗口").into()); }
    let data: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    if data.get("cancelled").and_then(|v| v.as_bool()) == Some(true) { return Ok(None); }
    let address = data.get("address").and_then(|v| v.as_str()).ok_or_else(|| invalid("缺少服务器地址"))?.trim();
    let port = data.get("port").and_then(|v| v.as_str()).ok_or_else(|| invalid("缺少服务器端口"))?.trim().parse::<u16>()?;
    Ok(Some((address.to_owned(), port)))
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
    let choice = unsafe { MessageBoxW(ptr::null_mut(), wide("从剪贴板导入复制的验证信息？选择“否”可从文件导入。").as_ptr(), wide("RustProxy 客户端").as_ptr(), 0x23) };
    if choice == 2 { return Ok(None); }
    let clipboard = if choice == 6 {
        use std::os::windows::process::CommandExt;
        let program = std::env::var_os("ProgramFiles").map(std::path::PathBuf::from)
            .map(|p| p.join("PowerShell").join("7").join("pwsh.exe")).filter(|p| p.is_file())
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"));
        let output = std::process::Command::new(program)
            .args(["-NoLogo", "-NoProfile", "-STA", "-Command", "Add-Type -AssemblyName System.Windows.Forms; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); [Console]::Out.Write([Windows.Forms.Clipboard]::GetText())"])
            .creation_flags(0x08000000).output()?;
        if !output.status.success() || output.stdout.len() > 65536 { return Err(invalid("无法读取剪贴板或内容过大").into()); }
        Some(output.stdout)
    } else { None };
    let source = if clipboard.is_none() { match dialog(false)? { Some(path) => Some(path), None => return Ok(None) } } else { None };
    let (address, port) = match tunnel_endpoint_dialog()? { Some(endpoint) => endpoint, None => return Ok(None) };
    let destination = match dialog(true)? { Some(path) => path, None => return Ok(None) };
    let ports = if let Some(raw) = clipboard { import_bytes(&raw, &destination, Some((&address, port)))? } else { import_endpoint(source.as_ref().unwrap(), &destination, &address, port)? };
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
    fn pasted_credentials_create_profile_with_tunnel_endpoint() {
        let dir = std::env::temp_dir().join(format!("rustproxy-paste-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir(&dir).unwrap();
        let destination = dir.join("client.json");
        let input = br#"{"uuid":"4f4ce912-06fe-48a4-9ea6-82419339a62e","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":"0123456789abcdef","server_name":"www.microsoft.com"}"#;
        import_bytes(input, &destination, Some(("tunnel.example.com", 54321))).unwrap();
        let output: serde_json::Value = serde_json::from_slice(&fs::read(&destination).unwrap()).unwrap();
        assert_eq!(output["server_address"], "tunnel.example.com");
        assert_eq!(output["server_port"], 54321);
        assert_eq!(output["short_id"], "0123456789abcdef");
        fs::remove_dir_all(dir).unwrap();
    }

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

    #[test]
    fn imports_profile_with_independent_tunnel_address_and_port() {
        let dir = std::env::temp_dir().join(format!("rustproxy-endpoint-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir(&dir).unwrap();
        let source = dir.join("source.json");
        let target = dir.join("target.json");
        let data = serde_json::json!({
            "server_address": "127.0.0.1", "server_port": 12345,
            "uuid": "4f4ce912-06fe-48a4-9ea6-82419339a62e",
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "short_id": "0123456789abcdef", "server_name": "www.microsoft.com"
        });
        let original = serde_json::to_vec(&data).unwrap();
        fs::write(&source, &original).unwrap();
        assert!(import_endpoint(&source, &target, "https://example.com", 443).is_err());
        assert!(import_endpoint(&source, &target, "example.com", 0).is_err());
        import_endpoint(&source, &target, "tunnel.example.com", 54321).unwrap();
        let saved: serde_json::Value = serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
        assert_eq!(saved["server_address"], "tunnel.example.com");
        assert_eq!(saved["server_port"], 54321);
        assert_eq!(saved["uuid"], data["uuid"]);
        assert_eq!(saved["public_key"], data["public_key"]);
        assert_eq!(fs::read(&source).unwrap(), original);
        assert!(import_endpoint(&source, &target, "tunnel.example.com", 54321).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
