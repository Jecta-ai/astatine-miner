//! Shared graceful-shutdown signalling for the mining runtime.
//!
//! Unix handles SIGINT and SIGTERM, and Linux additionally handles SIGHUP, all
//! through the same monitor. The delivery flag is set synchronously from the
//! operating-system signal handler (via `signal-hook`), not later by a runtime
//! task. That gives transaction signing a real linearization point: a signing
//! permit is refused if shutdown delivery is visible before the permit is
//! acquired. A permit acquired first classifies the signing section as already
//! in flight; its durable journal authorization and `Prepared` state are
//! preserved and it is never silently rebroadcast.
//!
//! macOS keeps the same SIGINT/SIGTERM graceful path and deliberately does not
//! install a SIGHUP handler, so terminal-hangup semantics remain unchanged.
//! Windows keeps the Tokio Ctrl+C handler.
//!
//! The operating system installs one signal handler at a time. A signal
//! delivered before its handler is installed retains the OS default
//! disposition. Mining and recovery install this signal at the start of the
//! command, before configuration, journal, or signing activity; the residual
//! process-start window cannot be made atomic with these OS APIs.

use std::{
    future::Future,
    io,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

/// The fallback poll interval for observing a synchronously delivered flag if
/// the async wake-up path loses a race during handler registration.
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[cfg(not(unix))]
const CTRL_C_CODE: usize = usize::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShutdownReason {
    #[cfg(unix)]
    Interrupt,
    #[cfg(unix)]
    Terminate,
    #[cfg(target_os = "linux")]
    Hangup,
    #[cfg(not(unix))]
    CtrlC,
}

impl ShutdownReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            #[cfg(unix)]
            Self::Interrupt => "SIGINT",
            #[cfg(unix)]
            Self::Terminate => "SIGTERM",
            #[cfg(target_os = "linux")]
            Self::Hangup => "SIGHUP",
            #[cfg(not(unix))]
            Self::CtrlC => "Ctrl+C",
        }
    }

    fn code(self) -> usize {
        #[cfg(unix)]
        {
            #[cfg(target_os = "linux")]
            use signal_hook::consts::signal::SIGHUP;
            use signal_hook::consts::signal::{SIGINT, SIGTERM};

            match self {
                Self::Interrupt => SIGINT as usize,
                Self::Terminate => SIGTERM as usize,
                #[cfg(target_os = "linux")]
                Self::Hangup => SIGHUP as usize,
            }
        }
        #[cfg(not(unix))]
        {
            CTRL_C_CODE
        }
    }

    fn from_code(code: usize) -> Option<Self> {
        if code == 0 {
            return None;
        }
        #[cfg(unix)]
        {
            #[cfg(target_os = "linux")]
            use signal_hook::consts::signal::SIGHUP;
            use signal_hook::consts::signal::{SIGINT, SIGTERM};

            if code == SIGINT as usize {
                Some(Self::Interrupt)
            } else if code == SIGTERM as usize {
                Some(Self::Terminate)
            } else {
                #[cfg(target_os = "linux")]
                if code == SIGHUP as usize {
                    return Some(Self::Hangup);
                }
                None
            }
        }
        #[cfg(not(unix))]
        {
            (code == CTRL_C_CODE).then_some(Self::CtrlC)
        }
    }

    #[cfg(test)]
    pub(crate) fn test_request_reason() -> Self {
        #[cfg(unix)]
        {
            Self::Terminate
        }
        #[cfg(not(unix))]
        {
            Self::CtrlC
        }
    }
}

/// Live delivery flags used by synchronous terminal prompts. Signal handlers
/// never touch this list; they only update the atomics owned by each request.
/// Prompts consult it while they wait so a signal can cancel a polling read
/// without mutating signal dispositions or using a detached reader thread.
static ACTIVE_PROMPT_REQUESTS: Mutex<Vec<Weak<AtomicUsize>>> = Mutex::new(Vec::new());

/// A blocking terminal prompt was cancelled because a shutdown signal was
/// delivered. Callers that own a `ShutdownSignal` treat this as a clean stop;
/// callers without one fail closed before mutating authorization state.
#[derive(Debug)]
pub(crate) struct PromptShutdown;

impl std::fmt::Display for PromptShutdown {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("terminal prompt cancelled by a shutdown signal")
    }
}

impl std::error::Error for PromptShutdown {}

pub(crate) fn prompt_shutdown_error() -> anyhow::Error {
    anyhow::Error::new(PromptShutdown)
}

pub(crate) fn is_prompt_shutdown(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<PromptShutdown>().is_some())
}

/// True while any live shutdown request has observed a delivered signal.
pub(crate) fn prompt_shutdown_requested() -> bool {
    let mut active = ACTIVE_PROMPT_REQUESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut requested = false;
    active.retain(|weak| {
        let Some(delivered) = weak.upgrade() else {
            return false;
        };
        requested |= delivered.load(Ordering::SeqCst) != 0;
        true
    });
    requested
}

/// Synchronous delivery flag and the signing-permit state shared with the
/// transaction manager.
#[derive(Clone)]
pub(crate) struct ShutdownRequest {
    delivered: Arc<AtomicUsize>,
    signing: Arc<AtomicBool>,
}

impl Default for ShutdownRequest {
    fn default() -> Self {
        Self::new(false)
    }
}

impl ShutdownRequest {
    /// `register_for_prompts` must only be true for requests backed by an
    /// installed OS signal handler. Bare signing-barrier requests used by tests
    /// and internal callers must not be able to cancel an unrelated terminal
    /// prompt in the same process.
    fn new(register_for_prompts: bool) -> Self {
        let delivered = Arc::new(AtomicUsize::new(0));
        if register_for_prompts {
            ACTIVE_PROMPT_REQUESTS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(Arc::downgrade(&delivered));
        }
        Self {
            delivered,
            signing: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg(test)]
    pub(crate) fn registered_for_test() -> Self {
        Self::new(true)
    }

    pub(crate) fn is_requested(&self) -> bool {
        self.delivered.load(Ordering::SeqCst) != 0
    }

    /// The first signal reason latched by `mark_delivered`. Later signals do
    /// not replace it; they only keep the shutdown state latched.
    pub(crate) fn reason(&self) -> Option<ShutdownReason> {
        ShutdownReason::from_code(self.delivered.load(Ordering::SeqCst))
    }

    /// Latch the first delivered signal reason. Later signals observe the
    /// already-nonzero flag and do not replace the reason reported to callers.
    fn mark_delivered(&self, reason: ShutdownReason) {
        let _ =
            self.delivered
                .compare_exchange(0, reason.code(), Ordering::SeqCst, Ordering::SeqCst);
    }

    /// Acquire the exclusive pre-signing permit.
    ///
    /// The successful compare-exchange followed by the second delivery check is
    /// the linearization point:
    /// - delivery visible before the second check refuses the permit;
    /// - delivery visible only after the second check means the signing section
    ///   was already in flight when shutdown was delivered.
    pub(crate) fn begin_signing(&self) -> Option<SigningPermit> {
        if self.is_requested() {
            return None;
        }
        if self
            .signing
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return None;
        }
        if self.is_requested() {
            self.signing.store(false, Ordering::SeqCst);
            return None;
        }
        Some(SigningPermit {
            signing: Arc::clone(&self.signing),
        })
    }

    #[cfg(test)]
    pub(crate) fn request_for_test(&self) {
        self.mark_delivered(ShutdownReason::test_request_reason());
    }
}

/// Held across a synchronous signing section. Dropping it releases the permit;
/// a delivered shutdown flag remains latched and refuses later permits.
#[must_use = "hold the signing permit across the signing section"]
pub(crate) struct SigningPermit {
    signing: Arc<AtomicBool>,
}

impl Drop for SigningPermit {
    fn drop(&mut self) {
        self.signing.store(false, Ordering::SeqCst);
    }
}

type ShutdownEvent = std::result::Result<ShutdownReason, String>;

/// Owns the OS signal monitor and provides a cancel-safe receive operation.
pub(crate) struct ShutdownSignal {
    request: ShutdownRequest,
    receiver: tokio::sync::watch::Receiver<Option<ShutdownEvent>>,
    task: tokio::task::JoinHandle<()>,
    #[cfg(unix)]
    signal_ids: Vec<signal_hook::SigId>,
    #[cfg(test)]
    sender: tokio::sync::watch::Sender<Option<ShutdownEvent>>,
}

#[cfg(test)]
pub(crate) const PROMPT_SIGNAL_TEST_ENV: &str = "ASTATINE_TEST_PROMPT_SIGNAL";

impl ShutdownSignal {
    pub(crate) fn new() -> io::Result<Self> {
        // Production commands must register their request for prompt
        // cancellation. Tests that run in the same process must not let one
        // test's delivered flag cancel an unrelated test's prompt, so only
        // disposable PTY child processes opt in explicitly.
        #[cfg(test)]
        let register_for_prompts = std::env::var_os(PROMPT_SIGNAL_TEST_ENV).is_some();
        #[cfg(not(test))]
        let register_for_prompts = true;
        Self::new_impl(register_for_prompts)
    }

    fn new_impl(register_for_prompts: bool) -> io::Result<Self> {
        let (sender, receiver) = tokio::sync::watch::channel(None);
        let request = ShutdownRequest::new(register_for_prompts);
        // Register the synchronous delivery flags first. Once this returns,
        // every delivered signal is visible to the signing barrier and to
        // blocking terminal prompts without waiting for the async monitor to
        // be scheduled. The async streams only carry the reason event and wake
        // the monitor; a signal between flag registration and stream creation
        // is still observed through the synchronous flag.
        #[cfg(unix)]
        let mut signal_ids = register_os_signal_flags(&request)?;
        let streams = match os_signal_streams() {
            Ok(streams) => streams,
            Err(error) => {
                #[cfg(unix)]
                for id in signal_ids.drain(..) {
                    signal_hook::low_level::unregister(id);
                }
                return Err(error);
            }
        };
        let task = tokio::spawn(monitor_os_signals(request.clone(), sender.clone(), streams));
        Ok(Self {
            request,
            receiver,
            task,
            #[cfg(unix)]
            signal_ids,
            #[cfg(test)]
            sender,
        })
    }

    /// A signal that never receives an OS event unless a test triggers it.
    #[cfg(test)]
    pub(crate) fn synthetic() -> Self {
        let (sender, receiver) = tokio::sync::watch::channel(None);
        let task = tokio::spawn(std::future::pending::<()>());
        Self {
            request: ShutdownRequest::new(false),
            receiver,
            task,
            #[cfg(unix)]
            signal_ids: Vec::new(),
            sender,
        }
    }

    pub(crate) fn request(&self) -> ShutdownRequest {
        self.request.clone()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_requested(&self) -> bool {
        self.request.is_requested()
    }

    /// Wait for the first shutdown signal. This is cancel-safe: the delivery
    /// flag is synchronous, and the watch channel retains the reason event even
    /// if the caller is cancelled by a surrounding `select!`.
    pub(crate) async fn recv(&mut self) -> io::Result<ShutdownReason> {
        loop {
            if let Some(reason) = self.request.reason() {
                return Ok(reason);
            }
            if self.request.is_requested() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "shutdown was delivered with an unknown signal code",
                ));
            }
            if let Some(event) = self.receiver.borrow_and_update().clone() {
                return event.map_err(io::Error::other);
            }
            tokio::select! {
                changed = self.receiver.changed() => {
                    changed.map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "shutdown signal monitor stopped before delivering a signal",
                        )
                    })?;
                }
                _ = tokio::time::sleep(SHUTDOWN_POLL_INTERVAL) => {}
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn trigger_for_test(&self, reason: ShutdownReason) {
        self.request.mark_delivered(reason);
        let _ = self.sender.send(Some(Ok(reason)));
    }
}

impl Drop for ShutdownSignal {
    fn drop(&mut self) {
        self.task.abort();
        #[cfg(unix)]
        for id in self.signal_ids.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}

async fn monitor_os_signals(
    request: ShutdownRequest,
    sender: tokio::sync::watch::Sender<Option<ShutdownEvent>>,
    streams: OsSignalStreams,
) {
    let event = wait_for_os_signal(streams)
        .await
        .map_err(|error| error.to_string());
    if let Ok(reason) = &event {
        request.mark_delivered(*reason);
    }
    let _ = sender.send(Some(event));
}

#[cfg(unix)]
fn register_os_signal_flags(request: &ShutdownRequest) -> io::Result<Vec<signal_hook::SigId>> {
    use signal_hook::consts::signal::{SIGINT, SIGTERM};

    #[cfg(target_os = "linux")]
    let signals: &[(libc::c_int, usize)] = &[
        (SIGINT, SIGINT as usize),
        (SIGTERM, SIGTERM as usize),
        (
            signal_hook::consts::signal::SIGHUP,
            signal_hook::consts::signal::SIGHUP as usize,
        ),
    ];
    #[cfg(not(target_os = "linux"))]
    let signals: &[(libc::c_int, usize)] =
        &[(SIGINT, SIGINT as usize), (SIGTERM, SIGTERM as usize)];

    let mut ids = Vec::with_capacity(signals.len());
    for (signal, code) in signals {
        let delivered = Arc::clone(&request.delivered);
        let code = *code;
        // SAFETY: the handler only performs a lock-free atomic compare-exchange,
        // which is async-signal-safe. It latches the first delivered signal so
        // later signals cannot replace the reason reported to the operator.
        match unsafe {
            signal_hook::low_level::register(*signal, move || {
                let _ = delivered.compare_exchange(0, code, Ordering::SeqCst, Ordering::SeqCst);
            })
        } {
            Ok(id) => ids.push(id),
            Err(error) => {
                for id in ids.drain(..) {
                    signal_hook::low_level::unregister(id);
                }
                return Err(io::Error::other(error.to_string()));
            }
        }
    }
    Ok(ids)
}

#[cfg(unix)]
struct OsSignalStreams {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
    #[cfg(target_os = "linux")]
    hangup: tokio::signal::unix::Signal,
}

#[cfg(unix)]
fn os_signal_streams() -> io::Result<OsSignalStreams> {
    use tokio::signal::unix::{SignalKind, signal};

    Ok(OsSignalStreams {
        interrupt: signal(SignalKind::interrupt())?,
        terminate: signal(SignalKind::terminate())?,
        #[cfg(target_os = "linux")]
        hangup: signal(SignalKind::hangup())?,
    })
}

#[cfg(unix)]
async fn wait_for_os_signal(streams: OsSignalStreams) -> io::Result<ShutdownReason> {
    let OsSignalStreams {
        mut interrupt,
        mut terminate,
        #[cfg(target_os = "linux")]
        mut hangup,
    } = streams;

    #[cfg(target_os = "linux")]
    {
        tokio::select! {
            received = interrupt.recv() => signal_reason(received, ShutdownReason::Interrupt),
            received = terminate.recv() => signal_reason(received, ShutdownReason::Terminate),
            received = hangup.recv() => signal_reason(received, ShutdownReason::Hangup),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        tokio::select! {
            received = interrupt.recv() => signal_reason(received, ShutdownReason::Interrupt),
            received = terminate.recv() => signal_reason(received, ShutdownReason::Terminate),
        }
    }
}

#[cfg(unix)]
fn signal_reason(received: Option<()>, reason: ShutdownReason) -> io::Result<ShutdownReason> {
    received.map(|()| reason).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "OS shutdown signal stream closed before delivering a signal",
        )
    })
}

/// A named unit type keeps the shared registration path free of a `()` local,
/// which Clippy rejects as `let_unit_value` on Windows.
#[cfg(not(unix))]
struct OsSignalStreams;

#[cfg(not(unix))]
fn os_signal_streams() -> io::Result<OsSignalStreams> {
    Ok(OsSignalStreams)
}

#[cfg(not(unix))]
async fn wait_for_os_signal(_: OsSignalStreams) -> io::Result<ShutdownReason> {
    tokio::signal::ctrl_c().await?;
    Ok(ShutdownReason::CtrlC)
}

/// Race an operation against the shared shutdown signal. The signal is polled
/// first so an already-delivered shutdown is observed before starting work.
pub(crate) async fn race_with_shutdown<F, T>(
    future: F,
    shutdown: &mut ShutdownSignal,
) -> std::result::Result<Option<T>, io::Error>
where
    F: Future<Output = T>,
{
    tokio::select! {
        biased;
        signal = shutdown.recv() => {
            signal?;
            Ok(None)
        }
        result = future => Ok(Some(result)),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ShutdownReason, ShutdownRequest, ShutdownSignal, SigningPermit, race_with_shutdown,
    };
    use std::{thread, time::Duration};

    fn test_reason() -> ShutdownReason {
        ShutdownReason::test_request_reason()
    }

    #[tokio::test]
    async fn shutdown_receive_is_cancel_safe() {
        let mut shutdown = ShutdownSignal::synthetic();
        assert!(!shutdown.is_requested());
        let cancelled = tokio::time::timeout(Duration::from_millis(10), shutdown.recv()).await;
        assert!(
            cancelled.is_err(),
            "synthetic signal must not resolve early"
        );

        shutdown.trigger_for_test(test_reason());
        let reason = tokio::time::timeout(Duration::from_secs(1), shutdown.recv())
            .await
            .expect("triggered shutdown signal should resolve")
            .expect("triggered shutdown signal should not fail");
        assert_eq!(reason, test_reason());
        assert!(shutdown.is_requested());
    }

    #[tokio::test]
    async fn shutdown_race_prefers_the_pending_signal_over_an_incomplete_operation() {
        let mut shutdown = ShutdownSignal::synthetic();
        shutdown.trigger_for_test(test_reason());
        let result = race_with_shutdown(std::future::pending::<()>(), &mut shutdown)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn shutdown_race_keeps_a_completed_operation() {
        let mut shutdown = ShutdownSignal::synthetic();
        let result = race_with_shutdown(async { 1439_u64 }, &mut shutdown)
            .await
            .unwrap();
        assert_eq!(result, Some(1439));
    }

    #[test]
    fn shutdown_request_is_monotonic_and_visible_across_threads() {
        let request = ShutdownRequest::default();
        let waiter = {
            let request = request.clone();
            thread::spawn(move || {
                while !request.is_requested() {
                    std::hint::spin_loop();
                }
            })
        };
        assert!(!request.is_requested());
        request.request_for_test();
        waiter.join().unwrap();
        assert!(request.is_requested());
        request.request_for_test();
        assert!(request.is_requested());
    }

    #[cfg(unix)]
    #[test]
    fn first_delivered_signal_reason_is_latched() {
        let request = ShutdownRequest::default();
        request.mark_delivered(ShutdownReason::Terminate);
        request.mark_delivered(ShutdownReason::Interrupt);
        assert_eq!(request.reason(), Some(ShutdownReason::Terminate));
        assert!(request.is_requested());
    }

    #[test]
    fn shutdown_barrier_refuses_a_permit_after_delivery() {
        let request = ShutdownRequest::default();
        request.request_for_test();
        assert!(
            request.begin_signing().is_none(),
            "delivery before permit acquisition must refuse signing"
        );
    }

    #[test]
    fn shutdown_barrier_classifies_an_acquired_permit_as_in_flight() {
        let request = ShutdownRequest::default();
        let permit: SigningPermit = request
            .begin_signing()
            .expect("permit should be available before delivery");
        request.request_for_test();
        assert!(request.is_requested());
        drop(permit);
        assert!(
            request.begin_signing().is_none(),
            "the delivered flag remains latched after the in-flight permit is released"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn supported_os_signals_resolve_the_shutdown_signal() {
        const CHILD: &str = "ASTATINE_TEST_SHUTDOWN_SIGNAL_CHILD";
        const SIGNAL: &str = "ASTATINE_TEST_SHUTDOWN_SIGNAL";

        if std::env::var_os(CHILD).is_none() {
            #[allow(unused_mut)]
            let mut signals = vec!["sigint", "sigterm"];
            #[cfg(target_os = "linux")]
            signals.push("sighup");
            for signal in signals {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "shutdown::tests::supported_os_signals_resolve_the_shutdown_signal",
                        "--nocapture",
                    ])
                    .env(CHILD, "1")
                    .env(SIGNAL, signal)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "child {signal} signal test failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            return;
        }

        let signal = std::env::var(SIGNAL).unwrap();
        let (signal_number, expected) = match signal.as_str() {
            "sigint" => (libc::SIGINT, ShutdownReason::Interrupt),
            "sigterm" => (libc::SIGTERM, ShutdownReason::Terminate),
            #[cfg(target_os = "linux")]
            "sighup" => (libc::SIGHUP, ShutdownReason::Hangup),
            other => panic!("unsupported child signal {other}"),
        };

        let mut shutdown = ShutdownSignal::new().unwrap();
        assert!(!shutdown.is_requested());
        // The synchronous signal-hook flag is registered by `new`, so raising
        // the signal in this isolated child process is safe even before the
        // monitor task is first polled.
        assert_eq!(unsafe { libc::raise(signal_number) }, 0);
        let reason = tokio::time::timeout(Duration::from_secs(2), shutdown.recv())
            .await
            .expect("OS signal should resolve the shutdown monitor")
            .expect("OS signal should not report a monitor failure");
        assert_eq!(reason, expected);
        assert!(shutdown.is_requested());
    }

    #[test]
    fn unregistered_signing_requests_do_not_cancel_terminal_prompts() {
        let request = ShutdownRequest::default();
        request.request_for_test();
        assert!(request.is_requested());
        assert!(
            !super::prompt_shutdown_requested(),
            "only requests backed by an installed OS handler may cancel a prompt"
        );
    }

    #[test]
    fn shutdown_request_flag_is_not_shared_between_independent_signals() {
        let first = ShutdownRequest::default();
        let second = ShutdownRequest::default();
        first.request_for_test();
        assert!(first.is_requested());
        assert!(!second.is_requested());
    }
}
