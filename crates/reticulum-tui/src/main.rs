use std::process::ExitCode;

use reticulum_tui::{config::parse_args, runtime};

#[tokio::main]
async fn main() -> ExitCode {
    let options = match parse_args(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("reticulum-tui: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime::run(options).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("reticulum-tui: {error}");
            ExitCode::FAILURE
        }
    }
}
