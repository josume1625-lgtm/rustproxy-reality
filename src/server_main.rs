mod server;
fn main() {
    if let Err(e) = server::run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
