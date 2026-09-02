//! Process boundary for the Canonical whole-company auditor.

use std::process::ExitCode;

use canonical_company_auditor::app::{Exit, execute};
use canonical_company_auditor::{cli, flags};
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    let argv = match utf8_argv() {
        Ok(argv) => argv,
        Err(error) => {
            eprintln!("canonical-auditor: {error}");
            return ExitCode::from(2);
        }
    };
    if let Err(error) = flags::validate_argv(&argv) {
        eprintln!("canonical-auditor: {error}");
        return ExitCode::from(2);
    }
    let cli = match cli::Cli::try_parse_from(&argv) {
        Ok(cli) => cli,
        Err(error) => {
            let code = u8::try_from(error.exit_code()).unwrap_or(2);
            let _ = error.print();
            return ExitCode::from(code);
        }
    };
    init_telemetry();

    match execute(cli).await {
        Ok(Exit::Success) => ExitCode::SUCCESS,
        Ok(Exit::FindingThreshold) => ExitCode::from(2),
        Err(error) => {
            tracing::error!(%error, "command failed");
            eprintln!("canonical-auditor: {error}");
            ExitCode::FAILURE
        }
    }
}

fn utf8_argv() -> Result<Vec<String>, &'static str> {
    std::env::args_os()
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| "command-line arguments must be valid UTF-8")
        })
        .collect()
}

fn init_telemetry() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if std::env::var("CANONICAL_LOG_FORMAT").as_deref() == Ok("json") {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .with_writer(std::io::stderr)
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .try_init();
    }
}
