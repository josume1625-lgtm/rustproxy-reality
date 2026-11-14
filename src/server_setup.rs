//! First-run setup. Configurations contain credentials and must be stored in a
//! user-private directory; only the client configuration is intended to be shared.
use serde_json::json;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub struct SetupResult {
    pub server_config: PathBuf,
    pub client_config: PathBuf,
    pub port: u16,
}

const DEFAULT_SERVER_NAME: &str = "www.microsoft.com";
const DEFAULT_DEST: &str = "www.microsoft.com:443";

/// Keep the Reality transport parameters internal to the common setup flow.
/// Traffic after authentication still leaves through the server's normal network.
pub fn quick_create(directory: &Path, address: &str, external: bool) -> Result<SetupResult> {
    if external && (address.eq_ignore_ascii_case("localhost")
        || address.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())) {
        return Err(invalid("external access needs a server address reachable by the client"));
    }
    let bind = if external { "0.0.0.0" } else { "127.0.0.1" };
    create(directory, address, DEFAULT_SERVER_NAME, DEFAULT_DEST, bind)
}

/// A local-only listener for a separate tunnelling program. Zero asks the OS
/// for a free port; the client later supplies the tunnel's public endpoint.
pub fn tunnel_create(directory: &Path, port: u16) -> Result<SetupResult> {
    create_with_port(directory, "127.0.0.1", DEFAULT_SERVER_NAME, DEFAULT_DEST, "127.0.0.1", port)
}

fn invalid(message: &str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_owned()).into()
}

fn xray_path() -> PathBuf {
    if let Some(path) = std::env::var_os("XRAY_BIN") { return PathBuf::from(path); }
    let name = if cfg!(windows) { "xray.exe" } else { "xray" };
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let path = dir.join(name);
            if path.is_file() { return path; }
        }
    }
    PathBuf::from(name)
}

fn xray_output(arg: &str) -> Result<Output> {
    let mut command = Command::new(xray_path());
    command.arg(arg);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let output = command.output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!("Xray {arg} failed with {}", output.status)).into());
    }
    Ok(output)
}

fn uuid() -> Result<String> {
    let output = xray_output("uuid")?;
    let value = String::from_utf8(output.stdout)?.trim().to_owned();
    let b = value.as_bytes();
    if b.len() != 36 || b.iter().enumerate().any(|(i, c)| {
        if [8, 13, 18, 23].contains(&i) { *c != b'-' } else { !c.is_ascii_hexdigit() }
    }) { return Err(invalid("unexpected Xray UUID output")); }
    Ok(value)
}

fn key_pair() -> Result<(String, String)> {
    let output = String::from_utf8(xray_output("x25519")?.stdout)?;
    let mut private = None;
    let mut public = None;
    for line in output.lines() {
        let Some((label, value)) = line.split_once(':') else { continue };
        match label.trim() {
            "PrivateKey" => private = Some(value.trim().to_owned()),
            "Password (PublicKey)" | "PublicKey" => public = Some(value.trim().to_owned()),
            _ => (),
        }
    }
    let valid_key = |s: &str| s.len() == 43 && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_');
    let private = private.filter(|s| valid_key(s)).ok_or_else(|| invalid("unexpected Xray private-key output"))?;
    let public = public.filter(|s| valid_key(s)).ok_or_else(|| invalid("unexpected Xray public-key output"))?;
    Ok((private, public))
}

fn validate_host(value: &str, label: &str) -> Result<()> {
    if value.trim() != value || value.is_empty() || value.len() > 253 || value.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\' | '@' | '?' | '#')) {
        return Err(invalid(&format!("invalid {label}")));
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

/// Create new server and client configurations without overwriting files.
/// `bind` is an explicit IP address; use 127.0.0.1 unless public access was
/// deliberately selected. The selected port is probed, not reserved: startup
/// may still fail if another process acquires it before Xray starts.
/// `address` must be the client-reachable hostname or IP, not inferred locally.
pub fn create(directory: &Path, address: &str, server_name: &str, dest: &str, bind: &str) -> Result<SetupResult> {
    create_with_port(directory, address, server_name, dest, bind, 0)
}

fn create_with_port(directory: &Path, address: &str, server_name: &str, dest: &str, bind: &str, requested_port: u16) -> Result<SetupResult> {
    validate_host(address, "client-facing server address")?;
    validate_host(server_name, "server name")?;
    validate_host(dest, "fallback destination")?;
    if !server_name.is_ascii() || server_name.split('.').any(|label| label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') || !label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')) {
        return Err(invalid("server name must be an ASCII DNS name"));
    }
    let (dest_host, dest_port) = dest.rsplit_once(':').ok_or_else(|| invalid("fallback destination must contain a port"))?;
    if dest_host.is_empty() || dest_port.parse::<u16>().ok().filter(|p| *p != 0).is_none() {
        return Err(invalid("fallback destination must contain a valid host and port"));
    }
    let ip: IpAddr = bind.parse().map_err(|_| invalid("listen address must be an IP address"))?;
    let listener = TcpListener::bind((ip, requested_port))?;
    let port = listener.local_addr()?.port();
    let (private_key, public_key) = key_pair()?;
    let client_uuid = uuid()?;
    let short_uuid = uuid()?;
    let short_id: String = short_uuid.chars().filter(|c| *c != '-').take(16).collect();
    let server = json!({"listen": bind, "port": port, "clients": [client_uuid], "dest": dest,
        "server_names": [server_name], "private_key": private_key, "short_ids": [short_id]});
    let client = json!({"server_address": address, "server_port": port, "uuid": client_uuid,
        "public_key": public_key, "short_id": short_id, "server_name": server_name,
        "socks_port": 1080, "http_port": 1081});
    let mut server_bytes = serde_json::to_vec_pretty(&server)?;
    let mut client_bytes = serde_json::to_vec_pretty(&client)?;
    server_bytes.push(b'\n');
    client_bytes.push(b'\n');
    fs::create_dir_all(directory)?;
    let server_path = directory.join("server_config.json");
    let client_path = directory.join("client_config.json");
    write_new(&server_path, &server_bytes)?;
    if let Err(error) = write_new(&client_path, &client_bytes) {
        let _ = fs::remove_file(&server_path);
        return Err(error.into());
    }
    drop(listener);
    Ok(SetupResult { server_config: server_path, client_config: client_path, port })
}

#[cfg(windows)]
fn utf16_base64(input: &str) -> String {
    let bytes: Vec<u8> = input.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        result.push(alphabet[(a >> 2) as usize] as char);
        result.push(alphabet[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        result.push(if chunk.len() > 1 { alphabet[(((b & 15) << 2) | (c >> 6)) as usize] as char } else { '=' });
        result.push(if chunk.len() > 2 { alphabet[(c & 63) as usize] as char } else { '=' });
    }
    result
}

/// Display the first-run wizard. The script is static; all entered values return
/// as JSON and are never interpolated into a shell command. Cancelling is safe.
#[cfg(windows)]
pub fn wizard(directory: &Path) -> Result<Option<SetupResult>> {
    use std::os::windows::process::CommandExt;
    let script = r#"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$form = New-Object System.Windows.Forms.Form
$form.Text = 'RustProxy 服务端设置'
$form.ClientSize = New-Object System.Drawing.Size(560, 250)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
function LabelAt($text, $top) {
  $label = New-Object System.Windows.Forms.Label
  $label.Text = $text; $label.Left = 20; $label.Top = $top; $label.Width = 520; $label.Height = 22
  $form.Controls.Add($label)
}
function TextAt($text, $top) {
  $field = New-Object System.Windows.Forms.TextBox
  $field.Text = $text; $field.Left = 20; $field.Top = $top; $field.Width = 520
  $form.Controls.Add($field)
  return $field
}
LabelAt '本地监听端口（留空或填 0 表示自动选择）' 15
$port = TextAt '' 40
LabelAt '将内网穿透程序指向 127.0.0.1 和所选端口。' 80
LabelAt '自动生成加密密钥，流量通过本机网络转发。' 110
LabelAt '连接文件含凭据，请只通过可信的加密渠道分享。' 140
$ok = New-Object System.Windows.Forms.Button
$ok.Text = '启动服务'; $ok.Left = 340; $ok.Top = 195; $ok.Width = 90
$ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
$cancel = New-Object System.Windows.Forms.Button
$cancel.Text = '取消'; $cancel.Left = 450; $cancel.Top = 195; $cancel.Width = 90
$cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.Controls.Add($ok); $form.Controls.Add($cancel)
$form.AcceptButton = $ok; $form.CancelButton = $cancel
$form.Add_FormClosing({
  param($sender, $event)
  if ($form.DialogResult -ne [System.Windows.Forms.DialogResult]::OK) { return }
  $p = 0
  if (-not [string]::IsNullOrWhiteSpace($port.Text) -and (-not [int]::TryParse($port.Text, [ref]$p) -or $p -lt 0 -or $p -gt 65535)) {
    [System.Windows.Forms.MessageBox]::Show('请输入 0 到 65535 之间的端口号。', 'RustProxy') | Out-Null
    $event.Cancel = $true
  }
})
if ($form.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
  [Console]::Out.Write('{"cancelled":true}')
} else {
  $v = @{ cancelled = $false; port = $(if ([string]::IsNullOrWhiteSpace($port.Text)) { 0 } else { [int]$port.Text }) }
  [Console]::Out.Write(($v | ConvertTo-Json -Compress))
}
$form.Dispose()
"#;
    // PowerShell 7 is preferred where installed; Windows PowerShell is the
    // built-in fallback on machines without PowerShell 7.
    let pwsh = std::env::var_os("ProgramFiles").map(PathBuf::from)
        .map(|p| p.join("PowerShell").join("7").join("pwsh.exe"));
    let executable = pwsh.filter(|p| p.is_file()).unwrap_or_else(|| {
        std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
            .join("System32").join("WindowsPowerShell").join("v1.0").join("powershell.exe")
    });
    let output = Command::new(executable).args(["-NoLogo", "-NoProfile", "-NonInteractive", "-STA", "-EncodedCommand", &utf16_base64(script)])
        .creation_flags(0x08000000).output()?;
    if !output.status.success() { return Err(io::Error::other("Unable to show the server setup dialog").into()); }
    let data: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    if data.get("cancelled").and_then(|v| v.as_bool()) == Some(true) { return Ok(None); }
    let port = data.get("port").and_then(|v| v.as_u64()).and_then(|p| u16::try_from(p).ok())
        .ok_or_else(|| invalid("invalid local port"))?;
    tunnel_create(directory, port).map(Some)
}

#[cfg(not(windows))]
pub fn wizard(_directory: &Path) -> Result<Option<SetupResult>> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "The setup dialog is available on Windows").into())
}
