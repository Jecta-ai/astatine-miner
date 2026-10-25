mod cli;
mod commands;
mod config;
mod contracts;
mod dashboard;
mod deployment;
mod diagnostics;
mod mining;
mod protocol;
mod rpc;
mod transaction;
mod wallet;

use std::process::ExitCode;

fn format_error_chain(error: &anyhow::Error) -> String {
    format!("{error:#}")
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = cli::parse();
    match commands::dispatch(cli.command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("astatine: {}", format_error_chain(&message));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::format_error_chain;

    #[test]
    fn cli_error_includes_the_underlying_cause_chain() {
        let error = anyhow::anyhow!("HTTP 503 from primary RPC")
            .context("read transaction receipt from configured RPC endpoints");

        let formatted = format_error_chain(&error);
        assert!(formatted.contains("read transaction receipt from configured RPC endpoints"));
        assert!(formatted.contains("HTTP 503 from primary RPC"));
    }
}
