mod server;
mod server_setup;
mod tray;
use std::{error::Error, path::{Path, PathBuf}};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn setup_wizard() -> Result<Option<PathBuf>> {
    let root = std::env::var_os("LOCALAPPDATA").ok_or("无法找到本地用户配置目录")?;
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis();
    let directory = PathBuf::from(root).join("RustProxy").join("servers").join(format!("profile-{stamp}-{}", std::process::id()));
    let Some(result) = server_setup::wizard(&directory)? else { return Ok(None) };
    let profile: serde_json::Value = serde_json::from_slice(&std::fs::read(&result.client_config)?)?;
    let credentials = serde_json::json!({"uuid": profile["uuid"], "public_key": profile["public_key"], "short_id": profile["short_id"], "server_name": profile["server_name"]});
    let details = serde_json::json!({"display":format!("本机监听：127.0.0.1:{}\n客户端验证信息：\n{}\n\n客户端配置：{}", result.port, serde_json::to_string_pretty(&credentials)?, result.client_config.display()),"credentials":serde_json::to_string(&credentials)?}).to_string();
    notify(&details);
    Ok(Some(result.server_config))
}

#[cfg(windows)]
fn notify(text: &str) {
    use std::os::windows::process::CommandExt;
    const SCRIPT: &str = r#"Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; [Console]::InputEncoding=[System.Text.UTF8Encoding]::new($false); $d=[Console]::In.ReadToEnd() | ConvertFrom-Json; $f=New-Object Windows.Forms.Form; $f.Text='RustProxy 连接密钥'; $f.ClientSize='640,360'; $f.StartPosition='CenterScreen'; $b=New-Object Windows.Forms.TextBox; $b.Multiline=$true; $b.ReadOnly=$true; $b.ScrollBars='Vertical'; $b.SetBounds(15,15,610,275); $b.Text=$d.display; $f.Controls.Add($b); $c=New-Object Windows.Forms.Button; $c.Text='复制验证信息'; $c.SetBounds(300,310,190,30); $c.Add_Click({[Windows.Forms.Clipboard]::SetText($d.credentials);$c.Text='已复制'}); $f.Controls.Add($c); $x=New-Object Windows.Forms.Button; $x.Text='关闭'; $x.SetBounds(510,310,90,30); $x.Add_Click({$f.Close()}); $f.Controls.Add($x); [void]$f.ShowDialog()"#;
    let program = std::env::var_os("ProgramFiles").map(std::path::PathBuf::from)
        .map(|p| p.join("PowerShell").join("7").join("pwsh.exe")).filter(|p| p.is_file())
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"));
    if let Ok(mut child) = std::process::Command::new(program)
        .args(["-NoLogo", "-NoProfile", "-STA", "-EncodedCommand", &server_setup::utf16_base64(SCRIPT)])
        .creation_flags(0x08000000).stdin(std::process::Stdio::piped()).spawn() {
        if let Some(mut stdin) = child.stdin.take() { use std::io::Write; let _ = stdin.write_all(text.as_bytes()); }
        let _ = child.wait();
    }
}
#[cfg(not(windows))]
fn notify(text: &str) { println!("{text}"); }

fn execute(args: &[String]) -> Result<()> {
    match args {
        [] => tray::run(None, false, Some(setup_wizard)),
        [cmd] if cmd == "tray" => tray::run(None, false, Some(setup_wizard)),
        [cmd, path] if cmd == "tray" => tray::run(Some(path), false, Some(setup_wizard)),
        [cmd, dir, port] if cmd == "local-setup" => {
            let result = server_setup::tunnel_create(Path::new(dir), port.parse()?)?;
            println!("server configuration: {}\nclient configuration: {}\nlocal port: {}", result.server_config.display(), result.client_config.display(), result.port);
            Ok(())
        },
        [cmd, dir, address, scope] if cmd == "quick-setup" => {
            let external = match scope.as_str() {
                "local" => false,
                "external" => true,
                _ => return Err("scope must be local or external".into()),
            };
            let result = server_setup::quick_create(Path::new(dir), address, external)?;
            println!("server configuration: {}\nclient configuration: {}\nport: {}", result.server_config.display(), result.client_config.display(), result.port);
            Ok(())
        },
        [cmd, dir, address, name, dest, bind] if cmd == "setup" => {
            let result = server_setup::create(Path::new(dir), address, name, dest, bind)?;
            println!("server configuration: {}\nclient configuration: {}\nport: {}", result.server_config.display(), result.client_config.display(), result.port);
            Ok(())
        },
        _ => server::run(args),
    }
}
fn main() {
    if let Err(e) = execute(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
