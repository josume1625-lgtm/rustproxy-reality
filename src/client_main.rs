mod client;
mod client_setup;
mod system_proxy;
mod tray;
use std::path::Path;

fn execute(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args {
        [] => tray::run(None, true, Some(client_setup::import_wizard)),
        [cmd] if cmd == "tray" => tray::run(None, true, Some(client_setup::import_wizard)),
        [cmd, path] if cmd == "tray" => tray::run(Some(path), true, Some(client_setup::import_wizard)),
        [cmd, source, dest] if cmd == "import-auto" => {
            let ports = client_setup::import_auto(Path::new(source), Path::new(dest))?;
            println!("SOCKS5: {}\nHTTP: {}", ports.socks_port, ports.http_port);
            Ok(())
        },
        [cmd, rest @ ..] if cmd == "system-proxy" => system_proxy::run(rest),
        _ => client::run(args),
    }
}
fn main() {
    if let Err(e) = execute(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
