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
    notify(&format!("配置已生成，本机监听地址：127.0.0.1:{}\n\n请将内网穿透程序的本地目标设为该地址。\n客户端连接文件：{}\n\n通过可信的加密方式分享客户端文件，在客户端填写穿透后的公网地址和端口。私钥和连接凭据以明文保存在本地，请限制目录访问。", result.port, result.client_config.display()));
    Ok(Some(result.server_config))
}

#[cfg(windows)]
fn notify(text: &str) {
    #[link(name="user32")] extern "system" { fn MessageBoxW(hwnd: *mut std::ffi::c_void, text: *const u16, caption: *const u16, flags: u32) -> i32; }
    let text: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
    let caption: Vec<u16> = "RustProxy 服务端".encode_utf16().chain(Some(0)).collect();
    unsafe { MessageBoxW(std::ptr::null_mut(), text.as_ptr(), caption.as_ptr(), 0x40); }
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
