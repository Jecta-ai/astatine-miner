mod cli;
mod commands;
mod config;
mod contracts;
mod dashboard;
mod deployment;
mod diagnostics;
mod gpu;
mod history_telemetry;
mod mining;
mod proof_telemetry;
mod protocol;
mod rpc;
mod startup;
mod transaction;
mod wallet;

use std::process::ExitCode;

fn format_error_chain(error: &anyhow::Error) -> String {
    diagnostics::terminal_text(&format!("{error:#}"))
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

    #[test]
    fn fatal_error_display_escapes_terminal_controls_and_bounds_length() {
        let error = anyhow::anyhow!(format!(
            "RPC \x1b]52;c;abc\x07\r\n\u{009b}\u{202e}{}",
            "x".repeat(5000)
        ));
        let rendered = format_error_chain(&error);
        assert!(!rendered.contains('\x1b') && !rendered.contains('\x07'));
        assert!(!rendered.contains('\r') && !rendered.contains('\n'));
        assert!(!rendered.contains('\u{009b}') && !rendered.contains('\u{202e}'));
        assert!(rendered.contains("RPC") && rendered.contains("truncated"));
        assert!(rendered.len() < 2048);
    }
}
