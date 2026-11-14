mod client;
mod system_proxy;
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let result = if args.first().is_some_and(|arg| arg == "system-proxy") {
        system_proxy::run(&args[1..])
    } else {
        client::run(&args)
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
