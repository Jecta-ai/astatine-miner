use crate::{cli::Network, diagnostics::DiagnosticBuffer};
use alloy_primitives::{Address, U256};
use anyhow::{Context, Result, anyhow};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};
use std::{
    io::{self, IsTerminal, Stdout, Write},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tokio::{
    sync::{Notify, watch},
    task::JoinHandle,
    time::{self, MissedTickBehavior},
};

const REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const INPUT_POLL_INTERVAL: Duration = Duration::from_millis(80);
const EMERALD: Color = Color::Rgb(41, 242, 107);
const AMBER: Color = Color::Rgb(245, 184, 72);
const ERROR_RED: Color = Color::Rgb(239, 83, 80);
const MUTED: Color = Color::Rgb(135, 145, 151);
const LIGHT: Color = Color::Rgb(220, 226, 229);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeStatus {
    Mining,
    Finalizing,
    Confirming,
    Waiting,
    Recovering,
    Paused,
    Ended,
    RpcError,
}

impl NodeStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Mining => "● MINING",
            Self::Finalizing => "FINALIZING",
            Self::Confirming => "CONFIRMING",
            Self::Waiting => "WAITING",
            Self::Recovering => "RECOVERING",
            Self::Paused => "PAUSED",
            Self::Ended => "ENDED",
            Self::RpcError => "RPC ERROR",
        }
    }

    fn color(self) -> Color {
        match self {
            Self::Mining => EMERALD,
            Self::Finalizing | Self::Confirming | Self::Recovering => AMBER,
            Self::RpcError => ERROR_RED,
            Self::Waiting | Self::Paused | Self::Ended => MUTED,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DashboardNode {
    pub id: u8,
    pub status: NodeStatus,
    pub expiry_timestamp: Option<u64>,
    pub mining_deadline: Option<Instant>,
    pub candidate: Option<Address>,
    pub reward: Option<U256>,
}

impl DashboardNode {
    pub fn status_at(&self, now: Instant) -> NodeStatus {
        if self.status == NodeStatus::Mining
            && self.mining_deadline.is_none_or(|deadline| now >= deadline)
        {
            NodeStatus::Waiting
        } else {
            self.status
        }
    }

    pub fn time_left(&self, model: &DashboardModel, now: Instant) -> Option<u64> {
        if self.status_at(now) != NodeStatus::Mining {
            return None;
        }
        let expiry = self.expiry_timestamp?;
        let elapsed = now
            .saturating_duration_since(model.snapshot_observed_at)
            .as_secs();
        let estimated_chain_time = model.block_timestamp.saturating_add(elapsed);
        let remaining = expiry.saturating_sub(estimated_chain_time);
        (remaining > 0).then_some(remaining)
    }
}

#[derive(Clone, Debug)]
pub struct DashboardModel {
    pub network: Network,
    pub chain_id: u64,
    pub wallet: Address,
    pub inj_balance: Option<U256>,
    pub cpu_threads: usize,
    pub session_limit: Option<U256>,
    pub session_exposure: Option<U256>,
    pub block_number: u64,
    pub block_timestamp: u64,
    pub snapshot_observed_at: Instant,
    pub selected_nodes: Vec<DashboardNode>,
    pub compute_only: bool,
    pub signing_enabled: bool,
    pub recovering: bool,
    pub stopping: bool,
    pub hashrate: f64,
    pub current_action: Option<String>,
    pub connection_error: Option<String>,
    pub critical_error: Option<String>,
}

impl DashboardModel {
    pub fn mode(&self, now: Instant) -> &'static str {
        if self.stopping {
            "STOPPING"
        } else if self.recovering {
            "RECOVERING"
        } else if self.connection_error.is_some() {
            "RPC ERROR"
        } else if !self
            .selected_nodes
            .iter()
            .any(|node| node.status_at(now) == NodeStatus::Mining)
        {
            "WAITING FOR WORK"
        } else if self.compute_only || !self.signing_enabled {
            "COMPUTE ONLY"
        } else {
            "LIVE MINING"
        }
    }
}

#[derive(Clone, Debug)]
enum DashboardEvent {
    StopRequested,
    Failure(String),
}

struct ActiveDashboard {
    shutdown: watch::Sender<bool>,
    renderer: JoinHandle<()>,
    input_stop: Arc<AtomicBool>,
    input_thread: Option<thread::JoinHandle<()>>,
}

type PanicHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync + 'static>;

struct PanicHookGuard {
    previous: Arc<Mutex<Option<PanicHook>>>,
}

#[derive(Clone, Default)]
pub struct DashboardSignal {
    state: Arc<SignalState>,
}

#[derive(Default)]
struct SignalState {
    event: Mutex<Option<DashboardEvent>>,
    notify: Notify,
    stop_requested: Arc<AtomicBool>,
}

pub struct Dashboard {
    model: Arc<RwLock<DashboardModel>>,
    diagnostics: DiagnosticBuffer,
    signal: DashboardSignal,
    terminal: Option<TerminalHandle>,
    panic_terminal: Arc<Mutex<Option<TerminalHandle>>>,
    panic_hook: Option<PanicHookGuard>,
    active: Option<ActiveDashboard>,
}

#[derive(Clone)]
pub struct DashboardUpdater {
    model: Arc<RwLock<DashboardModel>>,
}

#[derive(Clone)]
struct TerminalHandle {
    terminal: Arc<Mutex<Option<TerminalSession>>>,
}

struct RestoreTerminalOnDrop(TerminalHandle);

impl Dashboard {
    pub fn start(
        model: DashboardModel,
        hash_counter: Arc<AtomicU64>,
        diagnostics: DiagnosticBuffer,
    ) -> Result<Option<Self>> {
        let term = std::env::var("TERM").unwrap_or_default();
        if !io::stdin().is_terminal()
            || !io::stdout().is_terminal()
            || term.is_empty()
            || term == "dumb"
        {
            return Ok(None);
        }

        let model = Arc::new(RwLock::new(model));
        let mut dashboard = Self {
            model,
            diagnostics,
            signal: DashboardSignal::default(),
            terminal: None,
            panic_terminal: Arc::new(Mutex::new(None)),
            panic_hook: None,
            active: None,
        };
        dashboard.start_active(hash_counter)?;
        Ok(Some(dashboard))
    }

    pub fn update(&self, update: impl FnOnce(&mut DashboardModel)) {
        DashboardUpdater {
            model: Arc::clone(&self.model),
        }
        .update(update);
    }

    pub fn updater(&self) -> DashboardUpdater {
        DashboardUpdater {
            model: Arc::clone(&self.model),
        }
    }

    pub fn diagnostics(&self) -> DiagnosticBuffer {
        self.diagnostics.clone()
    }

    pub fn drain_diagnostics(&self) -> Vec<String> {
        self.diagnostics.drain()
    }

    pub fn signal(&self) -> DashboardSignal {
        self.signal.clone()
    }

    pub async fn suspend(&mut self) -> Result<()> {
        self.stop_active().await
    }

    pub fn resume(&mut self, hash_counter: Arc<AtomicU64>) -> Result<()> {
        if self.active.is_none() {
            self.start_active(hash_counter)?;
        }
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.update(|model| model.stopping = true);
        self.stop_active().await
    }

    fn start_active(&mut self, hash_counter: Arc<AtomicU64>) -> Result<()> {
        let terminal = TerminalHandle::new(
            TerminalSession::enter().context("initialize mining dashboard terminal")?,
        );
        *self
            .panic_terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(terminal.clone());
        if self.panic_hook.is_none() {
            self.panic_hook = Some(PanicHookGuard::install(Arc::clone(&self.panic_terminal)));
        }
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let input_stop = Arc::new(AtomicBool::new(false));
        let input_thread = spawn_input_thread(Arc::clone(&input_stop), self.signal.clone())?;

        let model = Arc::clone(&self.model);
        let diagnostics = self.diagnostics.clone();
        let signal = self.signal.clone();
        let stop_requested = Arc::clone(&self.signal.state.stop_requested);
        let render_terminal = terminal.clone();
        let term = std::env::var("TERM").unwrap_or_default();
        let colors = std::env::var_os("NO_COLOR").is_none() && !term.is_empty() && term != "dumb";
        let renderer_shutdown = shutdown_receiver.clone();
        let render_task = tokio::spawn(async move {
            render_loop(
                render_terminal,
                model,
                diagnostics,
                hash_counter,
                shutdown_receiver,
                stop_requested,
                colors,
            )
            .await
        });
        let renderer = tokio::spawn(async move {
            let result = render_task.await;
            let stopping = *renderer_shutdown.borrow();
            match result {
                Ok(Ok(())) if stopping => {}
                Ok(Ok(())) => signal.send(DashboardEvent::Failure(
                    "dashboard renderer stopped unexpectedly".to_owned(),
                )),
                Ok(Err(error)) => signal.send(DashboardEvent::Failure(format!("{error:#}"))),
                Err(error) => signal.send(DashboardEvent::Failure(format!(
                    "dashboard renderer task failed: {error}"
                ))),
            }
        });

        self.active = Some(ActiveDashboard {
            shutdown: shutdown_sender,
            renderer,
            input_stop,
            input_thread: Some(input_thread),
        });
        self.terminal = Some(terminal);
        Ok(())
    }

    async fn stop_active(&mut self) -> Result<()> {
        let Some(mut active) = self.active.take() else {
            return Ok(());
        };
        active.shutdown.send_replace(true);
        active.input_stop.store(true, Ordering::Release);
        let input_result = if let Some(input_thread) = active.input_thread.take() {
            tokio::task::spawn_blocking(move || input_thread.join())
                .await
                .context("join dashboard input thread")
                .and_then(|result| result.map_err(|_| anyhow!("dashboard input thread panicked")))
        } else {
            Ok(())
        };
        let renderer_result = active.renderer.await.context("join dashboard renderer");
        if let Some(terminal) = self.terminal.take() {
            terminal.restore();
        }
        self.panic_terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        input_result?;
        renderer_result?;
        Ok(())
    }
}

impl DashboardUpdater {
    pub fn update(&self, update: impl FnOnce(&mut DashboardModel)) {
        let mut model = self
            .model
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        update(&mut model);
    }
}

impl Drop for Dashboard {
    fn drop(&mut self) {
        if let Some(mut active) = self.active.take() {
            active.shutdown.send_replace(true);
            active.input_stop.store(true, Ordering::Release);
            if let Some(input_thread) = active.input_thread.take() {
                let _ = input_thread.join();
            }
        }
        if let Some(terminal) = self.terminal.take() {
            terminal.restore();
        }
        self.panic_terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        self.panic_hook.take();
        let mut stderr = io::stderr().lock();
        for message in self.diagnostics.drain() {
            let _ = writeln!(stderr, "astatine: {message}");
        }
    }
}

impl TerminalHandle {
    fn new(terminal: TerminalSession) -> Self {
        Self {
            terminal: Arc::new(Mutex::new(Some(terminal))),
        }
    }

    fn draw(
        &self,
        model: &DashboardModel,
        latest_diagnostic: Option<&str>,
        colors: bool,
    ) -> Result<()> {
        let mut terminal = self
            .terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let terminal = terminal
            .as_mut()
            .context("dashboard terminal has already been restored")?;
        terminal
            .terminal
            .draw(|frame| render_dashboard(frame, model, latest_diagnostic, colors))
            .context("draw mining dashboard")?;
        Ok(())
    }

    fn restore(&self) {
        self.terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
}

impl Drop for RestoreTerminalOnDrop {
    fn drop(&mut self) {
        self.0.restore();
    }
}

impl PanicHookGuard {
    fn install(terminal: Arc<Mutex<Option<TerminalHandle>>>) -> Self {
        let previous = Arc::new(Mutex::new(Some(std::panic::take_hook())));
        let previous_for_hook = Arc::clone(&previous);
        std::panic::set_hook(Box::new(move |panic| {
            if let Some(terminal) = terminal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
            {
                terminal.restore();
            }
            if let Some(previous) = previous_for_hook
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
            {
                previous(panic);
            }
        }));
        Self { previous }
    }
}

impl Drop for PanicHookGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        let _current = std::panic::take_hook();
        if let Some(previous) = self
            .previous
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            std::panic::set_hook(previous);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DashboardEventKind {
    StopRequested,
    Failure(String),
}

impl DashboardSignal {
    fn send(&self, event: DashboardEvent) {
        if matches!(event, DashboardEvent::StopRequested) {
            self.state.stop_requested.store(true, Ordering::Release);
        }
        *self
            .state
            .event
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(event);
        self.state.notify.notify_one();
    }

    pub async fn wait(&self) -> DashboardEventKind {
        loop {
            let event = self
                .state
                .event
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(event) = event {
                return match event {
                    DashboardEvent::StopRequested => DashboardEventKind::StopRequested,
                    DashboardEvent::Failure(error) => DashboardEventKind::Failure(error),
                };
            }
            self.state.notify.notified().await;
        }
    }
}

fn spawn_input_thread(
    stop: Arc<AtomicBool>,
    events: DashboardSignal,
) -> Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("astatine-dashboard-input".to_owned())
        .spawn(move || {
            while !stop.load(Ordering::Acquire) {
                match event::poll(INPUT_POLL_INTERVAL) {
                    Ok(false) => continue,
                    Ok(true) => match event::read() {
                        Ok(Event::Key(key))
                            if key.kind == KeyEventKind::Press
                                && key.code == KeyCode::Char('c')
                                && key.modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            events.send(DashboardEvent::StopRequested);
                            break;
                        }
                        Ok(_) => {}
                        Err(error) => {
                            events.send(DashboardEvent::Failure(format!(
                                "read dashboard keyboard event: {error}"
                            )));
                            break;
                        }
                    },
                    Err(error) => {
                        events.send(DashboardEvent::Failure(format!(
                            "poll dashboard keyboard: {error}"
                        )));
                        break;
                    }
                }
            }
        })
        .context("start dashboard input thread")
}

async fn render_loop(
    terminal: TerminalHandle,
    model: Arc<RwLock<DashboardModel>>,
    diagnostics: DiagnosticBuffer,
    hash_counter: Arc<AtomicU64>,
    mut shutdown: watch::Receiver<bool>,
    stop_requested: Arc<AtomicBool>,
    colors: bool,
) -> Result<()> {
    let _restore = RestoreTerminalOnDrop(terminal.clone());
    let mut ticker = time::interval(REFRESH_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut previous_hashes = hash_counter.load(Ordering::Relaxed);
    let mut previous_sample = Instant::now();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    draw_frame(
                        &terminal,
                        &model,
                        &diagnostics,
                        &stop_requested,
                        colors,
                        None,
                    )?;
                    return Ok(());
                }
            }
            _ = ticker.tick() => {
                let now = Instant::now();
                let hashes = hash_counter.load(Ordering::Relaxed);
                let elapsed = now.saturating_duration_since(previous_sample).as_secs_f64();
                let hashrate = hashes_per_second(previous_hashes, hashes, elapsed);
                previous_hashes = hashes;
                previous_sample = now;
                draw_frame(
                    &terminal,
                    &model,
                    &diagnostics,
                    &stop_requested,
                    colors,
                    Some(hashrate),
                )?;
            }
        }
    }
}

fn draw_frame(
    terminal: &TerminalHandle,
    model: &Arc<RwLock<DashboardModel>>,
    diagnostics: &DiagnosticBuffer,
    stop_requested: &AtomicBool,
    colors: bool,
    hashrate: Option<f64>,
) -> Result<()> {
    let mut snapshot = model
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    snapshot.stopping |= stop_requested.load(Ordering::Acquire);
    if let Some(hashrate) = hashrate {
        snapshot.hashrate = hashrate;
    }
    let latest_diagnostic = diagnostics.latest();
    terminal.draw(&snapshot, latest_diagnostic.as_deref(), colors)
}

fn render_dashboard(
    frame: &mut Frame<'_>,
    model: &DashboardModel,
    latest_diagnostic: Option<&str>,
    colors: bool,
) {
    let area = frame.area();
    if area.width < 20 || area.height == 0 {
        return;
    }
    if area.height <= 2 {
        let line = format!("ASTATINE • {} • Ctrl+C", model.mode(Instant::now()));
        frame.render_widget(Paragraph::new(line), area);
        return;
    }
    if area.width < 52 {
        render_narrow(frame, area, model, latest_diagnostic, colors);
    } else if area.width < 78 {
        render_compact(frame, area, model, latest_diagnostic, colors);
    } else {
        render_wide(frame, area, model, latest_diagnostic, colors);
    }
}

fn render_wide(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &DashboardModel,
    latest_diagnostic: Option<&str>,
    colors: bool,
) {
    let top_height = 8.min(area.height.saturating_sub(7));
    let header_area = Rect::new(area.x, area.y, area.width, top_height);
    render_wide_header(frame, header_area, model, colors);

    let remaining_y = area.y.saturating_add(top_height);
    let footer_y = area.y.saturating_add(area.height).saturating_sub(1);
    if remaining_y >= footer_y {
        render_footer(
            frame,
            Rect::new(area.x, footer_y, area.width, 1),
            model,
            latest_diagnostic,
            colors,
        );
        return;
    }
    render_rule(frame, Rect::new(area.x, remaining_y, area.width, 1), colors);
    let title_y = remaining_y.saturating_add(1);
    render_heading(
        frame,
        Rect::new(
            area.x.saturating_add(2),
            title_y,
            area.width.saturating_sub(4),
            1,
        ),
        model,
        colors,
    );
    let labels_y = title_y.saturating_add(1);
    render_column_labels(
        frame,
        Rect::new(
            area.x.saturating_add(2),
            labels_y,
            area.width.saturating_sub(4),
            1,
        ),
        colors,
    );
    let rows_start = labels_y.saturating_add(1);
    render_rule(frame, Rect::new(area.x, rows_start, area.width, 1), colors);
    let rows_y = rows_start.saturating_add(1);
    let rows_height = footer_y.saturating_sub(rows_y).saturating_sub(1);
    render_wide_rows(
        frame,
        Rect::new(
            area.x.saturating_add(2),
            rows_y,
            area.width.saturating_sub(4),
            rows_height,
        ),
        model,
        colors,
    );
    if footer_y > rows_y {
        render_rule(
            frame,
            Rect::new(area.x, footer_y.saturating_sub(1), area.width, 1),
            colors,
        );
    }
    render_footer(
        frame,
        Rect::new(area.x, footer_y, area.width, 1),
        model,
        latest_diagnostic,
        colors,
    );
}

fn render_wide_header(frame: &mut Frame<'_>, area: Rect, model: &DashboardModel, colors: bool) {
    if area.height == 0 {
        return;
    }
    let left_width = 31.min(area.width / 2);
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(left_width), Constraint::Min(0)])
        .split(area);
    let left = vec![
        Line::from(Span::styled("ASTATINE", style(colors, EMERALD, true))),
        version_mode_line(model, colors),
        Line::from(Span::styled("", Style::default())),
        Line::from(Span::styled(
            "Injective EVM miner",
            style(colors, MUTED, false),
        )),
    ];
    frame.render_widget(Paragraph::new(left), chunks[0]);
    let mut lines = vec![
        metadata_line("NETWORK", network_name(model.network), colors),
        metadata_line("CHAIN ID", &model.chain_id.to_string(), colors),
        metadata_line("WALLET", &short_address(model.wallet), colors),
        metadata_line("BALANCE", &format_optional_inj(model.inj_balance), colors),
        metadata_line("CPU", &format!("{} Threads", model.cpu_threads), colors),
        metadata_line("HASHRATE", &format_hashrate(model.hashrate), colors),
        metadata_line("SESSION", &format_session(model), colors),
    ];
    lines.truncate(usize::from(area.height));
    frame.render_widget(Paragraph::new(lines), chunks[1]);
}

fn render_compact(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &DashboardModel,
    latest_diagnostic: Option<&str>,
    colors: bool,
) {
    let header_height = 5.min(area.height.saturating_sub(5));
    let mut lines = vec![
        Line::from(Span::styled("ASTATINE", style(colors, EMERALD, true))),
        version_mode_line(model, colors),
        Line::from(Span::raw(format!(
            "{} • Chain {}",
            network_name(model.network),
            model.chain_id
        ))),
        Line::from(Span::raw(format!(
            "Wallet {} • INJ {}",
            short_address(model.wallet),
            format_optional_inj(model.inj_balance)
        ))),
        Line::from(Span::raw(format!(
            "CPU {} • {} • Session {}",
            model.cpu_threads,
            format_hashrate(model.hashrate),
            format_session(model)
        ))),
    ];
    lines.truncate(usize::from(header_height));
    frame.render_widget(
        Paragraph::new(lines),
        Rect::new(area.x, area.y, area.width, header_height),
    );

    let mut cursor = area.y.saturating_add(header_height);
    if cursor < area.y.saturating_add(area.height).saturating_sub(1) {
        render_rule(frame, Rect::new(area.x, cursor, area.width, 1), colors);
        cursor = cursor.saturating_add(1);
    }
    if cursor < area.y.saturating_add(area.height).saturating_sub(1) {
        render_heading(
            frame,
            Rect::new(
                area.x.saturating_add(1),
                cursor,
                area.width.saturating_sub(2),
                1,
            ),
            model,
            colors,
        );
        cursor = cursor.saturating_add(1);
    }
    if cursor < area.y.saturating_add(area.height).saturating_sub(1) {
        render_compact_column_labels(
            frame,
            Rect::new(
                area.x.saturating_add(1),
                cursor,
                area.width.saturating_sub(2),
                1,
            ),
            colors,
        );
        cursor = cursor.saturating_add(1);
    }
    if cursor < area.y.saturating_add(area.height).saturating_sub(1) {
        render_rule(frame, Rect::new(area.x, cursor, area.width, 1), colors);
        cursor = cursor.saturating_add(1);
    }
    let footer_y = area.y.saturating_add(area.height).saturating_sub(1);
    render_compact_rows(
        frame,
        Rect::new(
            area.x.saturating_add(1),
            cursor,
            area.width.saturating_sub(2),
            footer_y.saturating_sub(cursor),
        ),
        model,
        colors,
    );
    render_footer(
        frame,
        Rect::new(area.x, footer_y, area.width, 1),
        model,
        latest_diagnostic,
        colors,
    );
}

fn render_narrow(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &DashboardModel,
    latest_diagnostic: Option<&str>,
    colors: bool,
) {
    let header_height = 4.min(area.height.saturating_sub(2));
    let lines = vec![
        Line::from(Span::styled("ASTATINE", style(colors, EMERALD, true))),
        version_mode_line(model, colors),
        Line::from(Span::raw(format!(
            "{} · {}",
            network_name(model.network),
            model.chain_id
        ))),
        Line::from(Span::raw(format!(
            "{} · {} INJ",
            short_address(model.wallet),
            format_optional_inj(model.inj_balance)
        ))),
    ];
    frame.render_widget(
        Paragraph::new(lines),
        Rect::new(area.x, area.y, area.width, header_height),
    );
    let title_y = area.y.saturating_add(header_height);
    if title_y < area.y.saturating_add(area.height).saturating_sub(1) {
        render_heading(
            frame,
            Rect::new(area.x, title_y, area.width, 1),
            model,
            colors,
        );
    }
    let rows_y = title_y.saturating_add(1);
    let footer_y = area.y.saturating_add(area.height).saturating_sub(1);
    render_narrow_rows(
        frame,
        Rect::new(area.x, rows_y, area.width, footer_y.saturating_sub(rows_y)),
        model,
        colors,
    );
    render_footer(
        frame,
        Rect::new(area.x, footer_y, area.width, 1),
        model,
        latest_diagnostic,
        colors,
    );
}

fn render_heading(frame: &mut Frame<'_>, area: Rect, model: &DashboardModel, colors: bool) {
    let heading = format!(
        "MINING NODES  {}",
        if area.width >= 28 {
            format!("{} selected / 9 total", model.selected_nodes.len())
        } else {
            format!(" {} / 9", model.selected_nodes.len())
        }
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            heading,
            style(colors, LIGHT, true),
        ))),
        area,
    );
}

fn render_column_labels(frame: &mut Frame<'_>, area: Rect, colors: bool) {
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!(
                "{:<6}{:<14}{:<10}{:<22}{}",
                "NODE", "STATUS", "TIME LEFT", "BEST MINER", "WINDOW REWARD"
            ),
            style(colors, MUTED, false),
        ))),
        area,
    );
}

fn render_compact_column_labels(frame: &mut Frame<'_>, area: Rect, colors: bool) {
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "ID  STATUS  TIME  BEST MINER  REWARD",
            style(colors, MUTED, false),
        ))),
        area,
    );
}

fn render_wide_rows(frame: &mut Frame<'_>, area: Rect, model: &DashboardModel, colors: bool) {
    let now = Instant::now();
    let lines = model
        .selected_nodes
        .iter()
        .map(|node| wide_node_line(node, model, now, colors))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_compact_rows(frame: &mut Frame<'_>, area: Rect, model: &DashboardModel, colors: bool) {
    let now = Instant::now();
    let lines = model
        .selected_nodes
        .iter()
        .map(|node| compact_node_line(node, model, now, colors))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_narrow_rows(frame: &mut Frame<'_>, area: Rect, model: &DashboardModel, colors: bool) {
    let now = Instant::now();
    let mut lines = Vec::with_capacity(model.selected_nodes.len() * 2);
    for node in &model.selected_nodes {
        let status = node.status_at(now);
        let time = node
            .time_left(model, now)
            .map(format_time_left)
            .unwrap_or_else(|| "--:--".to_owned());
        lines.push(Line::from(vec![
            Span::styled(format!("{:02} ", node.id), style(colors, MUTED, false)),
            Span::styled(
                format!("{} ", status.label()),
                style(colors, status.color(), true),
            ),
            Span::styled(time, style(colors, LIGHT, false)),
        ]));
        lines.push(narrow_candidate_reward_line(node, model, colors));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

fn wide_node_line(
    node: &DashboardNode,
    model: &DashboardModel,
    now: Instant,
    colors: bool,
) -> Line<'static> {
    let status = node.status_at(now);
    let time = node
        .time_left(model, now)
        .map(format_time_left)
        .unwrap_or_else(|| "--:--".to_owned());
    let candidate = candidate_spans(node.candidate, model.wallet, 22, colors);
    let reward = format_reward(node.reward);
    let mut spans = vec![
        Span::styled(format!("{:02}    ", node.id), style(colors, LIGHT, false)),
        Span::styled(
            format!("{:<12}  ", status.label()),
            style(colors, status.color(), true),
        ),
        Span::styled(format!("{time:<8}  "), style(colors, LIGHT, false)),
    ];
    let candidate_width = candidate
        .iter()
        .map(|span| span.content.chars().count())
        .sum::<usize>();
    spans.extend(candidate);
    spans.push(Span::raw(
        " ".repeat(22_usize.saturating_sub(candidate_width)),
    ));
    spans.push(Span::styled(reward, style(colors, LIGHT, false)));
    Line::from(spans)
}

fn compact_node_line(
    node: &DashboardNode,
    model: &DashboardModel,
    now: Instant,
    colors: bool,
) -> Line<'static> {
    let status = node.status_at(now);
    let time = node
        .time_left(model, now)
        .map(format_time_left)
        .unwrap_or_else(|| "--:--".to_owned());
    let mut spans = vec![
        Span::styled(format!("{:02} ", node.id), style(colors, MUTED, false)),
        Span::styled(
            format!("{} ", status.label()),
            style(colors, status.color(), true),
        ),
        Span::styled(format!("{time} "), style(colors, LIGHT, false)),
    ];
    spans.extend(candidate_spans(node.candidate, model.wallet, 16, colors));
    spans.push(Span::raw(" "));
    spans.push(Span::styled(
        format_reward(node.reward),
        style(colors, LIGHT, false),
    ));
    Line::from(spans)
}

fn narrow_candidate_reward_line(
    node: &DashboardNode,
    model: &DashboardModel,
    colors: bool,
) -> Line<'static> {
    let mut spans = vec![Span::styled("  BEST ", style(colors, MUTED, false))];
    spans.extend(candidate_spans(node.candidate, model.wallet, 12, colors));
    spans.push(Span::styled(" · ", style(colors, MUTED, false)));
    spans.push(Span::styled(
        format_reward(node.reward),
        style(colors, LIGHT, false),
    ));
    Line::from(spans)
}

fn candidate_spans(
    candidate: Option<Address>,
    wallet: Address,
    max_chars: usize,
    colors: bool,
) -> Vec<Span<'static>> {
    let Some(candidate) = candidate else {
        return vec![Span::styled("None", style(colors, MUTED, false))];
    };
    let is_ours = candidate == wallet;
    let address = short_address(candidate);
    let address = fit_text(&address, max_chars);
    if is_ours {
        vec![
            Span::styled(address, style(colors, EMERALD, true)),
            Span::styled(" YOU", style(colors, EMERALD, true)),
        ]
    } else {
        vec![Span::styled(address, style(colors, LIGHT, false))]
    }
}

fn render_footer(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &DashboardModel,
    latest_diagnostic: Option<&str>,
    colors: bool,
) {
    let (text, tint) = if let Some(error) = model.critical_error.as_deref() {
        (format!("ERROR • {error}"), ERROR_RED)
    } else if let Some(error) = model.connection_error.as_deref() {
        (format!("RPC ERROR • {error}"), ERROR_RED)
    } else if let Some(action) = model.current_action.as_deref() {
        (
            format!(
                "{action} • Block {} • Ctrl+C to stop",
                format_block(model.block_number)
            ),
            AMBER,
        )
    } else if let Some(diagnostic) = latest_diagnostic {
        (format!("Notice • {diagnostic} • Ctrl+C to stop"), AMBER)
    } else if !model.signing_enabled {
        (
            format!(
                "Block {} • Potential reward • Signing off • Ctrl+C to stop",
                format_block(model.block_number)
            ),
            MUTED,
        )
    } else {
        (
            format!(
                "Connected • Block {} • Window reward is potential • Ctrl+C to stop",
                format_block(model.block_number)
            ),
            MUTED,
        )
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(text, style(colors, tint, false)))),
        area,
    );
}

fn render_rule(frame: &mut Frame<'_>, area: Rect, colors: bool) {
    if area.width == 0 {
        return;
    }
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "─".repeat(usize::from(area.width)),
            style(colors, Color::Rgb(54, 74, 63), false),
        ))),
        area,
    );
}

fn metadata_line(label: &str, value: &str, colors: bool) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<9}"), style(colors, MUTED, false)),
        Span::styled(value.to_owned(), style(colors, LIGHT, false)),
    ])
}

fn version_mode_line(model: &DashboardModel, colors: bool) -> Line<'static> {
    let mode = model.mode(Instant::now());
    let mode_color = match mode {
        "LIVE MINING" => EMERALD,
        "RECOVERING" | "STOPPING" => AMBER,
        "RPC ERROR" => ERROR_RED,
        _ => MUTED,
    };
    Line::from(vec![
        Span::styled(
            format!("v{} • ", env!("CARGO_PKG_VERSION")),
            style(colors, LIGHT, false),
        ),
        Span::styled(mode.to_owned(), style(colors, mode_color, true)),
    ])
}

fn style(colors: bool, foreground: Color, bold: bool) -> Style {
    if !colors {
        return Style::default();
    }
    let style = Style::default().fg(foreground);
    if bold {
        style.add_modifier(Modifier::BOLD)
    } else {
        style
    }
}

pub fn format_time_left(seconds: u64) -> String {
    format!("{:02}:{:02}", seconds / 60, seconds % 60)
}

fn hashes_per_second(previous: u64, current: u64, elapsed_secs: f64) -> f64 {
    current.wrapping_sub(previous) as f64 / elapsed_secs.max(0.001)
}

pub fn format_reward(value: Option<U256>) -> String {
    value
        .map(|value| format!("{} AST", format_units(value, 9)))
        .unwrap_or_else(|| "-- AST".to_owned())
}

pub fn format_units(value: U256, decimals: u8) -> String {
    let scale = U256::from(10_u8).pow(U256::from(decimals));
    let whole = value / scale;
    let fraction = value % scale;
    if fraction.is_zero() {
        return whole.to_string();
    }
    let fractional = format!("{fraction:0>width$}", width = usize::from(decimals));
    format!("{whole}.{}", fractional.trim_end_matches('0'))
}

fn format_optional_inj(value: Option<U256>) -> String {
    value
        .map(|value| format!("{} INJ", format_units(value, 18)))
        .unwrap_or_else(|| "-- INJ".to_owned())
}

fn format_session(model: &DashboardModel) -> String {
    match (model.session_exposure, model.session_limit) {
        (Some(exposure), Some(limit)) => format!(
            "{} / {} INJ",
            format_units(exposure, 18),
            format_units(limit, 18)
        ),
        _ => "--".to_owned(),
    }
}

fn format_hashrate(rate: f64) -> String {
    if !rate.is_finite() || rate < 0.0 {
        return "-- H/s".to_owned();
    }
    if rate >= 1_000_000.0 {
        format!("{:.2} MH/s", rate / 1_000_000.0)
    } else if rate >= 1_000.0 {
        format!("{:.1} kH/s", rate / 1_000.0)
    } else {
        format!("{rate:.0} H/s")
    }
}

fn format_block(block: u64) -> String {
    let value = block.to_string();
    let mut result = String::with_capacity(value.len() + value.len() / 3);
    for (index, digit) in value.chars().enumerate() {
        if index > 0 && (value.len() - index).is_multiple_of(3) {
            result.push(',');
        }
        result.push(digit);
    }
    result
}

fn short_address(address: Address) -> String {
    let value = format!("{address:#x}");
    format!("{}...{}", &value[..6], &value[value.len() - 4..])
}

fn network_name(network: Network) -> &'static str {
    match network {
        Network::Testnet => "Injective Testnet",
        Network::Mainnet => "Injective Mainnet",
    }
}

fn fit_text(value: &str, max_chars: usize) -> String {
    let count = value.chars().count();
    if count <= max_chars {
        return value.to_owned();
    }
    value.chars().take(max_chars).collect()
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    raw_mode: bool,
}

impl TerminalSession {
    fn enter() -> io::Result<Self> {
        let terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        let mut session = Self {
            terminal,
            raw_mode: false,
        };
        execute!(session.terminal.backend_mut(), EnterAlternateScreen)?;
        enable_raw_mode()?;
        session.raw_mode = true;
        session.terminal.hide_cursor()?;
        session.terminal.clear()?;
        Ok(session)
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        if self.raw_mode {
            let _ = disable_raw_mode();
            self.raw_mode = false;
        }
        let backend = self.terminal.backend_mut();
        let _ = execute!(backend, crossterm::cursor::Show, LeaveAlternateScreen);
        let _ = backend.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DashboardModel, DashboardNode, NodeStatus, format_hashrate, format_reward,
        format_time_left, format_units, hashes_per_second, render_dashboard,
    };
    use crate::cli::Network;
    use alloy_primitives::{Address, U256};
    use ratatui::{Terminal, backend::TestBackend};
    use std::time::{Duration, Instant};

    fn wallet(last: u8) -> Address {
        Address::with_last_byte(last)
    }

    fn model(nodes: Vec<DashboardNode>) -> DashboardModel {
        DashboardModel {
            network: Network::Testnet,
            chain_id: 1439,
            wallet: wallet(1),
            inj_balance: Some(U256::from(2_948_000_000_000_000_000_u128)),
            cpu_threads: 6,
            session_limit: Some(U256::from(500_000_000_000_000_000_u128)),
            session_exposure: Some(U256::from(52_000_000_000_000_000_u128)),
            block_number: 144_123_456,
            block_timestamp: 1_000,
            snapshot_observed_at: Instant::now(),
            selected_nodes: nodes,
            compute_only: false,
            signing_enabled: true,
            recovering: false,
            stopping: false,
            hashrate: 184_200.0,
            current_action: None,
            connection_error: None,
            critical_error: None,
        }
    }

    fn node(id: u8, status: NodeStatus, candidate: Option<Address>) -> DashboardNode {
        DashboardNode {
            id,
            status,
            expiry_timestamp: Some(1_160),
            mining_deadline: Some(Instant::now() + Duration::from_secs(160)),
            candidate,
            reward: Some(U256::from(900_000_000_u64)),
        }
    }

    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
        let buffer = terminal.backend().buffer();
        let area = buffer.area;
        (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn selected_nodes_are_rendered_in_id_order_and_best_miner_is_truthful() {
        let mut view = model(vec![
            node(7, NodeStatus::Mining, Some(wallet(1))),
            node(1, NodeStatus::Waiting, None),
            node(3, NodeStatus::Finalizing, Some(wallet(2))),
        ]);
        view.selected_nodes.sort_by_key(|node| node.id);
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &view, None, false))
            .unwrap();
        let text = buffer_text(&terminal);
        let one = text.find("01    WAITING").unwrap();
        let three = text.find("03    FINALIZING").unwrap();
        let seven = text.find("07    ● MINING").unwrap();
        assert!(one < three && three < seven);
        assert!(text.contains("None"));
        assert!(text.contains("YOU"));
        assert!(text.contains("0x0000...0002"));
        assert!(
            !text.lines().any(|line| line.starts_with("  02    ")),
            "{text}"
        );
    }

    #[test]
    fn all_nine_nodes_fit_a_standard_terminal_and_only_selected_rows_are_shown() {
        let nodes = (1..=9)
            .rev()
            .map(|id| node(id, NodeStatus::Mining, None))
            .collect::<Vec<_>>();
        let mut view = model(nodes);
        view.selected_nodes.sort_by_key(|node| node.id);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &view, None, false))
            .unwrap();
        let text = buffer_text(&terminal);
        for id in 1..=9 {
            assert!(text.contains(&format!("{id:02}    ● MINING")));
        }
        assert!(text.contains("9 selected / 9 total"));
        assert!(!text.contains("10  "));
    }

    #[test]
    fn exact_rewards_countdowns_and_hashrate_formats_are_readable() {
        assert_eq!(format_reward(Some(U256::from(900_000_000_u64))), "0.9 AST");
        assert_eq!(format_reward(Some(U256::from(1_u8))), "0.000000001 AST");
        assert_eq!(format_reward(None), "-- AST");
        assert_eq!(format_time_left(161), "02:41");
        assert_eq!(
            format_units(U256::from(2_948_000_000_000_000_000_u128), 18),
            "2.948"
        );
        assert_eq!(format_hashrate(184_200.0), "184.2 kH/s");
        assert_eq!(hashes_per_second(100, 1_100, 2.0), 500.0);
        assert_eq!(hashes_per_second(u64::MAX - 1, 1, 1.0), 3.0);
    }

    #[test]
    fn deadline_and_expiry_never_render_positive_time_after_work_stops() {
        let observed = Instant::now();
        let mut view = model(vec![DashboardNode {
            id: 1,
            status: NodeStatus::Mining,
            expiry_timestamp: Some(1_060),
            mining_deadline: Some(observed + Duration::from_secs(60)),
            candidate: None,
            reward: None,
        }]);
        view.snapshot_observed_at = observed;
        assert_eq!(view.selected_nodes[0].time_left(&view, observed), Some(60));
        assert_eq!(
            view.selected_nodes[0].time_left(&view, observed + Duration::from_secs(1)),
            Some(59)
        );
        assert_eq!(
            view.selected_nodes[0].status_at(observed + Duration::from_secs(60)),
            NodeStatus::Waiting
        );
        assert_eq!(
            view.selected_nodes[0].time_left(&view, observed + Duration::from_secs(60)),
            None
        );
        view.selected_nodes[0].status = NodeStatus::Paused;
        assert_eq!(
            view.selected_nodes[0].time_left(&view, observed + Duration::from_secs(1)),
            None
        );
    }

    #[test]
    fn mode_distinguishes_signing_compute_only_waiting_recovery_and_stopping() {
        let mut view = model(vec![node(1, NodeStatus::Mining, None)]);
        assert_eq!(view.mode(Instant::now()), "LIVE MINING");
        view.compute_only = true;
        assert_eq!(view.mode(Instant::now()), "COMPUTE ONLY");
        view.compute_only = false;
        view.signing_enabled = false;
        assert_eq!(view.mode(Instant::now()), "COMPUTE ONLY");
        view.signing_enabled = true;
        view.selected_nodes[0].status = NodeStatus::Waiting;
        assert_eq!(view.mode(Instant::now()), "WAITING FOR WORK");
        view.connection_error = Some("RPC unavailable".to_owned());
        assert_eq!(view.mode(Instant::now()), "RPC ERROR");
        view.connection_error = None;
        view.recovering = true;
        assert_eq!(view.mode(Instant::now()), "RECOVERING");
        view.stopping = true;
        assert_eq!(view.mode(Instant::now()), "STOPPING");
    }

    #[test]
    fn narrow_dashboard_does_not_wrap_or_panic_and_keeps_selected_nodes() {
        let view = model(vec![
            node(1, NodeStatus::RpcError, None),
            node(3, NodeStatus::Waiting, Some(wallet(2))),
            node(7, NodeStatus::Mining, Some(wallet(1))),
        ]);
        let mut terminal = Terminal::new(TestBackend::new(48, 24)).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &view, Some("temporary RPC warning"), false))
            .unwrap();
        let text = buffer_text(&terminal);
        assert!(text.contains("ASTATINE"));
        assert!(text.contains("01 RPC ERROR"));
        assert!(text.contains("03 WAITING"));
        assert!(text.contains("07 ● MINING"));
        assert!(text.contains("YOU"));
        assert!(text.lines().all(|line| line.chars().count() <= 48));
    }

    #[test]
    fn transaction_exposure_and_critical_footer_are_displayed_without_guessing() {
        let mut view = model(vec![node(1, NodeStatus::Confirming, None)]);
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| {
                render_dashboard(frame, &view, None, false);
            })
            .unwrap();
        assert!(buffer_text(&terminal).contains("0.052 / 0.5 INJ"));

        view.session_exposure = None;
        view.connection_error = Some("snapshot unavailable".to_owned());
        terminal
            .draw(|frame| render_dashboard(frame, &view, None, false))
            .unwrap();
        let text = buffer_text(&terminal);
        assert!(text.contains("CONFIRMING"));
        assert!(text.contains("RPC ERROR • snapshot unavailable"));
        assert!(text.contains("SESSION"));
        assert!(text.contains("--"));

        view.connection_error = None;
        view.critical_error = Some("transaction journal verification failed".to_owned());
        terminal
            .draw(|frame| render_dashboard(frame, &view, None, false))
            .unwrap();
        let text = buffer_text(&terminal);
        assert!(text.contains("ERROR • transaction journal verification failed"));
        assert!(!text.contains("RPC ERROR"));
    }
}
