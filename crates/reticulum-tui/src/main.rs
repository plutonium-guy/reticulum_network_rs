use std::process::ExitCode;

use reticulum_tui::config::{load_config, parse_args};

fn main() -> ExitCode {
    let options = match parse_args(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("reticulum-tui: {error}");
            return ExitCode::FAILURE;
        }
    };
    match load_config(options.config_path.as_deref()) {
        Ok(config) => {
            println!("{config:?}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("reticulum-tui: {error}");
            ExitCode::FAILURE
        }
    }
}
