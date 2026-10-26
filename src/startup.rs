use crossterm::{
    cursor::MoveToColumn,
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{Clear, ClearType},
};
use std::{
    future::Future,
    io::{self, IsTerminal, Write},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const FRAME_INTERVAL: Duration = Duration::from_millis(120);
const PLAIN_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

pub(crate) type CtrlCSignal = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

struct ActiveStep {
    label: String,
    started_at: Instant,
    last_heartbeat_at: Instant,
}

#[derive(Default)]
struct ProgressState {
    header_printed: bool,
    subtitle: Option<String>,
    subtitle_printed: bool,
    active: Option<ActiveStep>,
    paused: bool,
    frame: usize,
}

struct ProgressInner {
    state: Mutex<ProgressState>,
    writer: Mutex<Box<dyn Write + Send>>,
    interactive: bool,
    colors: bool,
    stopped: AtomicBool,
}

pub(crate) struct StartupProgress {
    inner: Arc<ProgressInner>,
    ticker: Option<thread::JoinHandle<()>>,
}

impl StartupProgress {
    pub(crate) fn start() -> Self {
        let stderr = io::stderr();
        let term = std::env::var("TERM").unwrap_or_default();
        let interactive = stderr.is_terminal() && !term.is_empty() && term != "dumb";
        let colors = interactive && std::env::var_os("NO_COLOR").is_none();
        Self::with_writer(Box::new(stderr), interactive, colors, true)
    }

    fn with_writer(
        writer: Box<dyn Write + Send>,
        interactive: bool,
        colors: bool,
        animate: bool,
    ) -> Self {
        let inner = Arc::new(ProgressInner {
            state: Mutex::new(ProgressState::default()),
            writer: Mutex::new(writer),
            interactive,
            colors,
            stopped: AtomicBool::new(false),
        });
        let ticker = if animate {
            let weak = Arc::downgrade(&inner);
            thread::Builder::new()
                .name("astatine-startup-progress".to_owned())
                .spawn(move || progress_ticker(weak))
                .ok()
        } else {
            None
        };
        let progress = Self { inner, ticker };
        progress.write_header();
        progress
    }

    pub(crate) fn set_network(&self, network: &str) {
        let mut state = self.lock_state();
        state.subtitle = Some(network.to_owned());
        let _ = self.write_header_locked(&mut state);
    }

    pub(crate) fn begin(&self, label: impl Into<String>) {
        let label = label.into();
        let mut state = self.lock_state();
        let now = Instant::now();
        state.active = Some(ActiveStep {
            label: label.clone(),
            started_at: now,
            last_heartbeat_at: now,
        });
        state.paused = false;
        if self.inner.interactive {
            let _ = self.render_active_locked(&mut state);
        } else {
            let _ = self.write_plain_locked(&format!("⋯ {label}"));
        }
    }

    pub(crate) fn update(&self, label: impl Into<String>) {
        let label = label.into();
        let mut state = self.lock_state();
        let Some(active) = state.active.as_mut() else {
            return;
        };
        if active.label == label {
            return;
        }
        active.label = label.clone();
        active.last_heartbeat_at = Instant::now();
        if self.inner.interactive {
            let _ = self.render_active_locked(&mut state);
        } else {
            let _ = self.write_plain_locked(&format!("⋯ {label}"));
        }
    }

    pub(crate) fn complete(&self, label: impl Into<String>) -> Duration {
        self.finish_step("✓", label.into())
    }

    pub(crate) fn warn(&self, label: impl Into<String>) -> Duration {
        self.finish_step("!", label.into())
    }

    pub(crate) fn fail(&self, details: impl Into<String>) -> Duration {
        let details = details.into();
        let mut state = self.lock_state();
        let elapsed = state
            .active
            .take()
            .map(|active| active.started_at.elapsed())
            .unwrap_or_default();
        state.paused = false;
        let label = if details.is_empty() {
            "Startup failed".to_owned()
        } else {
            details
        };
        let _ = self.write_status_locked(&mut state, "✗", &label, elapsed, StatusTone::Error);
        elapsed
    }

    pub(crate) fn note(&self, details: impl AsRef<str>) {
        let mut state = self.lock_state();
        let _ = self.write_plain_locked(&format!("! {}", details.as_ref()));
        if self.inner.interactive && state.active.is_some() && !state.paused {
            let _ = self.render_active_locked(&mut state);
        }
    }

    pub(crate) fn pause_for_prompt(&self, label: &str) {
        let mut state = self.lock_state();
        state.paused = true;
        if self.inner.interactive {
            let mut writer = self.lock_writer();
            let _ = clear_active_line(&mut *writer);
        }
        let _ = self.write_plain_locked(label);
    }

    pub(crate) fn resume_after_prompt(&self, label: impl Into<String>) {
        let label = label.into();
        let mut state = self.lock_state();
        let now = Instant::now();
        if let Some(active) = state.active.as_mut() {
            active.label = label.clone();
            active.started_at = now;
            active.last_heartbeat_at = now;
        } else {
            state.active = Some(ActiveStep {
                label: label.clone(),
                started_at: now,
                last_heartbeat_at: now,
            });
        }
        state.paused = false;
        if self.inner.interactive {
            let _ = self.render_active_locked(&mut state);
        } else {
            let _ = self.write_plain_locked(&format!("⋯ {label}"));
        }
    }

    pub(crate) fn cancel(&self) {
        self.warn("Startup cancelled by Ctrl+C");
        self.stop_ticker();
    }

    pub(crate) fn miner_ready(&self) {
        self.complete("Mining workers prepared");
        let mut state = self.lock_state();
        let _ = self.write_status_locked(
            &mut state,
            "✓",
            "Miner ready",
            Duration::ZERO,
            StatusTone::Success,
        );
        drop(state);
        self.stop_ticker();
    }

    fn finish_step(&self, marker: &'static str, label: String) -> Duration {
        let mut state = self.lock_state();
        let elapsed = state
            .active
            .take()
            .map(|active| active.started_at.elapsed())
            .unwrap_or_default();
        state.paused = false;
        let tone = if marker == "✓" {
            StatusTone::Success
        } else {
            StatusTone::Warning
        };
        let _ = self.write_status_locked(&mut state, marker, &label, elapsed, tone);
        elapsed
    }

    fn write_header(&self) {
        let mut state = self.lock_state();
        let _ = self.write_header_locked(&mut state);
    }

    fn write_header_locked(&self, state: &mut ProgressState) -> io::Result<()> {
        let mut writer = self.lock_writer();
        if !state.header_printed {
            if self.inner.colors {
                execute!(
                    writer,
                    SetForegroundColor(Color::Green),
                    Print("ASTATINE · STARTUP\n"),
                    ResetColor
                )?;
            } else {
                writeln!(writer, "ASTATINE · STARTUP")?;
            }
            state.header_printed = true;
        }
        if let Some(subtitle) = &state.subtitle
            && !state.subtitle_printed
        {
            writeln!(writer, "{subtitle}")?;
            state.subtitle_printed = true;
        }
        writer.flush()?;
        Ok(())
    }

    fn write_status_locked(
        &self,
        state: &mut ProgressState,
        marker: &str,
        label: &str,
        elapsed: Duration,
        tone: StatusTone,
    ) -> io::Result<()> {
        let mut writer = self.lock_writer();
        if self.inner.interactive {
            clear_active_line(&mut *writer)?;
        }
        let duration = if elapsed.is_zero() {
            String::new()
        } else {
            format!(" · {}", format_elapsed(elapsed))
        };
        if self.inner.colors {
            execute!(
                writer,
                SetForegroundColor(tone.color()),
                Print(format!("{marker} {label}{duration}\n")),
                ResetColor
            )?;
        } else {
            writeln!(writer, "{marker} {label}{duration}")?;
        }
        writer.flush()?;
        state.frame = 0;
        Ok(())
    }

    fn render_active_locked(&self, state: &mut ProgressState) -> io::Result<()> {
        let Some(active) = state.active.as_ref() else {
            return Ok(());
        };
        if state.paused || !self.inner.interactive {
            return Ok(());
        }
        let spinner = ["◐", "◓", "◑", "◒"][state.frame % 4];
        state.frame = state.frame.wrapping_add(1);
        let line = format!(
            "{spinner} {} · {}",
            active.label,
            format_elapsed(active.started_at.elapsed())
        );
        let mut writer = self.lock_writer();
        clear_active_line(&mut *writer)?;
        if self.inner.colors {
            execute!(
                writer,
                SetForegroundColor(Color::Green),
                Print(line),
                ResetColor
            )?;
        } else {
            write!(writer, "{line}")?;
        }
        writer.flush()
    }

    fn write_plain_locked(&self, line: &str) -> io::Result<()> {
        let mut writer = self.lock_writer();
        if self.inner.interactive {
            clear_active_line(&mut *writer)?;
        }
        writeln!(writer, "{line}")?;
        writer.flush()
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, ProgressState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_writer(&self) -> std::sync::MutexGuard<'_, Box<dyn Write + Send>> {
        self.inner
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn stop_ticker(&self) {
        self.inner.stopped.store(true, Ordering::Release);
        if let Some(ticker) = &self.ticker
            && ticker.thread().id() != thread::current().id()
        {
            ticker.thread().unpark();
        }
    }
}

impl Drop for StartupProgress {
    fn drop(&mut self) {
        self.inner.stopped.store(true, Ordering::Release);
        if let Some(ticker) = self.ticker.take() {
            let _ = ticker.join();
        }
        let mut state = self.lock_state();
        if let Some(active) = state.active.take() {
            let _ = self.write_status_locked(
                &mut state,
                "!",
                &format!("{} stopped before completion", active.label),
                active.started_at.elapsed(),
                StatusTone::Warning,
            );
        } else if self.inner.interactive {
            let mut writer = self.lock_writer();
            let _ = clear_active_line(&mut *writer);
        }
    }
}

#[derive(Clone, Copy)]
enum StatusTone {
    Success,
    Warning,
    Error,
}

impl StatusTone {
    fn color(self) -> Color {
        match self {
            Self::Success => Color::Green,
            Self::Warning => Color::Yellow,
            Self::Error => Color::Red,
        }
    }
}

fn clear_active_line<W: Write>(writer: &mut W) -> io::Result<()> {
    execute!(writer, MoveToColumn(0), Clear(ClearType::CurrentLine))
}

fn format_elapsed(elapsed: Duration) -> String {
    format!("{:.1}s", elapsed.as_secs_f64())
}

fn progress_ticker(inner: std::sync::Weak<ProgressInner>) {
    loop {
        thread::park_timeout(if inner.upgrade().is_some_and(|inner| inner.interactive) {
            FRAME_INTERVAL
        } else {
            Duration::from_secs(1)
        });
        let Some(inner) = inner.upgrade() else {
            return;
        };
        if inner.stopped.load(Ordering::Acquire) {
            return;
        }
        let mut state = inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.active.is_none() {
            continue;
        }
        if state.paused {
            continue;
        }
        if inner.interactive {
            let label = state.active.as_ref().unwrap().label.clone();
            let elapsed = state.active.as_ref().unwrap().started_at.elapsed();
            let spinner = ["◐", "◓", "◑", "◒"][state.frame % 4];
            state.frame = state.frame.wrapping_add(1);
            let line = format!("{spinner} {label} · {}", format_elapsed(elapsed));
            let mut writer = inner
                .writer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = clear_active_line(&mut *writer);
            if inner.colors {
                let _ = execute!(
                    writer,
                    SetForegroundColor(Color::Green),
                    Print(line),
                    ResetColor
                );
            } else {
                let _ = write!(writer, "{line}");
            }
            let _ = writer.flush();
        } else {
            let now = Instant::now();
            let Some(active) = state.active.as_mut() else {
                continue;
            };
            if now.saturating_duration_since(active.last_heartbeat_at) < PLAIN_HEARTBEAT_INTERVAL {
                continue;
            }
            active.last_heartbeat_at = now;
            let message = format!(
                "⋯ {} · still running ({})",
                active.label,
                format_elapsed(active.started_at.elapsed())
            );
            let mut writer = inner
                .writer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = writeln!(writer, "{message}");
            let _ = writer.flush();
        }
    }
}

pub(crate) async fn race_with_ctrl_c<F, T>(
    future: F,
    ctrl_c: &mut CtrlCSignal,
) -> Result<Option<T>, io::Error>
where
    F: Future<Output = T>,
{
    tokio::select! {
        result = future => Ok(Some(result)),
        signal = ctrl_c.as_mut() => {
            signal?;
            Ok(None)
        }
    }
}

#[cfg(test)]
fn progress_ticker_once(inner: &Arc<ProgressInner>) {
    let mut state = inner
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(active) = state.active.as_mut() else {
        return;
    };
    let now = Instant::now();
    if now.saturating_duration_since(active.last_heartbeat_at) < PLAIN_HEARTBEAT_INTERVAL {
        return;
    }
    active.last_heartbeat_at = now;
    let message = format!(
        "⋯ {} · still running ({})",
        active.label,
        format_elapsed(active.started_at.elapsed())
    );
    let mut writer = inner
        .writer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = writeln!(writer, "{message}");
    let _ = writer.flush();
}

#[cfg(test)]
mod tests {
    use super::{CtrlCSignal, PLAIN_HEARTBEAT_INTERVAL, StartupProgress, race_with_ctrl_c};
    use std::{
        io::{self, Write},
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    #[derive(Clone)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn plain_progress() -> (StartupProgress, Arc<Mutex<Vec<u8>>>) {
        let output = Arc::new(Mutex::new(Vec::new()));
        let progress = StartupProgress::with_writer(
            Box::new(Buffer(Arc::clone(&output))),
            false,
            false,
            false,
        );
        (progress, output)
    }

    fn captured_output(output: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8(output.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn successful_startup_stages_render_actual_completion() {
        let (progress, output) = plain_progress();
        progress.set_network("Injective EVM Testnet");
        progress.begin("Loading configuration");
        progress.complete("Configuration loaded");
        progress.begin("Connecting to RPC · validating Chain ID");
        progress.complete("RPC verified · Chain ID 1439");
        progress.begin("Verifying AST token");
        progress.complete("AST token verified");
        progress.begin("Verifying mining contracts · 0/9");
        progress.update("Verifying mining contracts · 6/9");
        progress.complete("Mining contracts verified · 9/9");
        progress.begin("Recovering previous transactions");
        progress.complete("Transaction recovery complete");
        progress.begin("Unlocking wallet");
        progress.pause_for_prompt("Unlock wallet");
        progress.resume_after_prompt("Decrypting Ethereum V3 keystore");
        progress.complete("Wallet unlocked");
        progress.begin("Loading latest mining work");
        progress.complete("Latest mining work loaded · block #123");
        progress.begin("Preparing mining workers · 0/2");
        progress.update("Preparing mining workers · 2/2");
        progress.miner_ready();
        let rendered = captured_output(&output);
        assert!(rendered.contains("ASTATINE · STARTUP"));
        assert!(rendered.contains("Injective EVM Testnet"));
        assert!(rendered.contains("Configuration loaded"));
        assert!(rendered.contains("RPC verified · Chain ID 1439"));
        assert!(rendered.contains("AST token verified"));
        assert!(rendered.contains("Verifying mining contracts · 6/9"));
        assert!(rendered.contains("Mining contracts verified · 9/9"));
        assert!(rendered.contains("Transaction recovery complete"));
        assert!(rendered.contains("Unlock wallet"));
        assert!(rendered.contains("Wallet unlocked"));
        assert!(rendered.contains("Latest mining work loaded · block #123"));
        assert!(rendered.contains("Preparing mining workers · 2/2"));
        assert!(rendered.contains("✓ Miner ready"));

        let recovery = rendered.find("Transaction recovery complete").unwrap();
        let unlock = rendered.find("Unlock wallet").unwrap();
        let wallet_unlocked = rendered.find("Wallet unlocked").unwrap();
        let latest_work = rendered.find("Latest mining work loaded").unwrap();
        let worker_prep = rendered.find("Preparing mining workers · 2/2").unwrap();
        let ready = rendered.find("✓ Miner ready").unwrap();
        assert!(recovery < unlock);
        assert!(unlock < wallet_unlocked);
        assert!(wallet_unlocked < latest_work);
        assert!(latest_work < worker_prep);
        assert!(worker_prep < ready);
    }

    #[test]
    fn slow_startup_step_emits_elapsed_heartbeat() {
        let (progress, output) = plain_progress();
        progress.begin("Connecting to RPC · Chain ID 1439");
        {
            let mut state = progress.lock_state();
            let active = state.active.as_mut().unwrap();
            active.started_at = Instant::now() - PLAIN_HEARTBEAT_INTERVAL - Duration::from_secs(2);
            active.last_heartbeat_at = Instant::now() - PLAIN_HEARTBEAT_INTERVAL;
        }
        super::progress_ticker_once(&progress.inner);
        assert!(captured_output(&output).contains("still running"));
        assert!(captured_output(&output).contains("Connecting to RPC · Chain ID 1439"));
    }

    #[test]
    fn failed_step_includes_specific_details() {
        let (progress, output) = plain_progress();
        progress.begin("Verifying mining contracts · 3/9");
        progress.note("Node 4 verification failed: runtime hash mismatch");
        progress.fail("Node 4 verification failed: runtime hash mismatch");
        let rendered = captured_output(&output);
        assert!(rendered.contains("Node 4 verification failed"));
        assert!(rendered.contains("runtime hash mismatch"));
    }

    #[test]
    fn redirected_progress_never_contains_ansi_sequences() {
        let (progress, output) = plain_progress();
        progress.begin("Recovering previous transactions");
        progress.complete("Transaction recovery complete");
        assert!(!captured_output(&output).contains('\u{1b}'));
    }

    #[test]
    fn interactive_startup_progress_does_not_enter_dashboard_terminal_modes() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let progress =
            StartupProgress::with_writer(Box::new(Buffer(Arc::clone(&output))), true, false, false);
        progress.begin("Unlocking wallet");
        progress.pause_for_prompt("Unlock wallet");
        drop(progress);
        let rendered = captured_output(&output);
        assert!(!rendered.contains("\u{1b}[?1049h"));
        assert!(!rendered.contains("\u{1b}[?25l"));
    }

    #[test]
    fn pausing_for_wallet_prompt_clears_active_progress_and_resumes_decryption() {
        let (progress, output) = plain_progress();
        progress.begin("Unlocking wallet");
        progress.pause_for_prompt("Unlock wallet");
        progress.resume_after_prompt("Decrypting Ethereum V3 keystore");
        progress.complete("Wallet unlocked");
        let rendered = captured_output(&output);
        assert!(rendered.contains("Unlock wallet"));
        assert!(rendered.contains("Decrypting Ethereum V3 keystore"));
        assert!(rendered.contains("Wallet unlocked"));
    }

    #[test]
    fn dropping_startup_progress_reports_an_unfinished_stage() {
        let (progress, output) = plain_progress();
        progress.begin("Loading latest mining work");
        drop(progress);
        assert!(
            captured_output(&output)
                .contains("Loading latest mining work stopped before completion")
        );
    }

    #[tokio::test]
    async fn ctrl_c_cancels_a_pending_startup_operation() {
        let mut ctrl_c: CtrlCSignal = Box::pin(async { Ok(()) });
        let result = race_with_ctrl_c(std::future::pending::<()>(), &mut ctrl_c)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn startup_operation_completes_before_ctrl_c() {
        let mut ctrl_c: CtrlCSignal = Box::pin(std::future::pending());
        let result = race_with_ctrl_c(async { 1439_u64 }, &mut ctrl_c)
            .await
            .unwrap();
        assert_eq!(result, Some(1439));
    }
}
