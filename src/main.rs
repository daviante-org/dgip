//! Binary entrypoint for `dgip` (HTTP server + operational CLI).

#[tokio::main]
async fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let code = dgip::cli::run_cli(args).await;
    if code != 0 {
        std::process::exit(code);
    }
}
