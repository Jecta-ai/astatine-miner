//! Disposable controlling-terminal helpers for Unix process tests.
//!
//! These helpers are compiled only into the test binary. They deliberately use
//! a real PTY and a new session/controlling terminal so `/dev/tty` prompts are
//! exercised instead of an in-memory mock.

use std::{
    fs::File,
    io::{self, Write},
    os::fd::{AsRawFd, FromRawFd},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

pub(crate) struct PtyChild {
    pub(crate) child: Child,
    master: File,
    output: String,
    finished: bool,
}

impl Drop for PtyChild {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let _ = self.child.kill();
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if self.child.try_wait().ok().flatten().is_some() {
                self.finished = true;
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl PtyChild {
    pub(crate) fn read_until(&mut self, needle: &str, timeout: Duration) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            if self.output.contains(needle) {
                return self.output.clone();
            }
            if Instant::now() >= deadline {
                return self.output.clone();
            }
            self.read_available(Duration::from_millis(100));
        }
    }

    pub(crate) fn write_all(&mut self, bytes: &[u8]) {
        self.master.write_all(bytes).unwrap();
        self.master.flush().unwrap();
    }

    pub(crate) fn signal(&self, signal: libc::c_int) {
        // SAFETY: `child.id()` is the live child PID for the lifetime of this
        // helper, and `kill` does not dereference memory.
        assert_eq!(
            unsafe { libc::kill(self.child.id() as libc::pid_t, signal) },
            0,
            "failed to signal PTY child with {signal}"
        );
    }

    pub(crate) fn wait_for_exit(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            self.read_available(Duration::ZERO);
            if let Some(status) = self.child.try_wait().unwrap() {
                self.finished = true;
                return Some(status);
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let grace = Instant::now() + Duration::from_secs(1);
                while Instant::now() < grace {
                    if let Some(status) = self.child.try_wait().unwrap() {
                        self.finished = true;
                        return Some(status);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub(crate) fn drain_available(&mut self, timeout: Duration) -> String {
        self.read_available(timeout);
        self.output.clone()
    }

    pub(crate) fn stdin_termios() -> libc::termios {
        tcgetattr(libc::STDIN_FILENO).expect("read standard-input termios")
    }

    pub(crate) fn assert_stdin_terminal_restored(original: &libc::termios) {
        let restored = tcgetattr(libc::STDIN_FILENO).expect("read restored standard-input termios");
        assert_termios_restored(&restored, original);
    }

    fn read_available(&mut self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let mut descriptor = libc::pollfd {
                fd: self.master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let millis = if remaining.is_zero() {
                0
            } else {
                i32::try_from(remaining.as_millis().min(100)).unwrap_or(100)
            };
            // SAFETY: one valid `pollfd` is supplied and the timeout is
            // non-negative.
            let ready = unsafe { libc::poll(&mut descriptor, 1, millis) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return;
            }
            if ready == 0 {
                return;
            }
            let mut buffer = [0_u8; 4096];
            // SAFETY: the buffer is valid for its full length.
            let count = unsafe {
                libc::read(
                    self.master.as_raw_fd(),
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if count <= 0 {
                return;
            }
            self.output
                .push_str(&String::from_utf8_lossy(&buffer[..count as usize]));
        }
    }
}

/// Spawn the current test executable under a fresh PTY. The child test body
/// must call [`attach_controlling_terminal`] before any `/dev/tty` prompt.
pub(crate) fn spawn_pty_test_child(test_name: &str, env: &[(&str, &str)]) -> PtyChild {
    let mut master_fd = -1;
    let mut slave_fd = -1;
    // SAFETY: `openpty` writes two valid descriptors on success. No name,
    // termios, or window-size overrides are supplied.
    let result = unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(result, 0, "openpty failed: {}", io::Error::last_os_error());
    // SAFETY: the descriptors are uniquely owned by this function.
    let master = unsafe { File::from_raw_fd(master_fd) };
    // SAFETY: the descriptors are uniquely owned by this function.
    let slave = unsafe { File::from_raw_fd(slave_fd) };
    let stdin = slave.try_clone().unwrap();
    let stdout = slave.try_clone().unwrap();
    let stderr = slave.try_clone().unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test_name, "--nocapture"])
        .env("NO_COLOR", "1")
        .env(crate::shutdown::PROMPT_SIGNAL_TEST_ENV, "1")
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/definitely-unavailable-astatine-pty-test-bus",
        )
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    for (key, value) in env {
        command.env(key, value);
    }
    let child = command.spawn().unwrap();
    drop(slave);
    PtyChild {
        child,
        master,
        output: String::new(),
        finished: false,
    }
}

/// Make the PTY inherited on standard input the child's controlling terminal.
/// The child test body runs in a fresh session, so `/dev/tty` resolves to this
/// disposable PTY even when the outer test runner has no controlling terminal.
pub(crate) fn attach_controlling_terminal() {
    // SAFETY: `setsid` has no pointer arguments and is safe to call before the
    // test body starts any I/O. The test child is not a process-group leader.
    let session = unsafe { libc::setsid() };
    assert_ne!(session, -1, "setsid failed: {}", io::Error::last_os_error());
    // SAFETY: standard input is the PTY slave inherited from the parent, and
    // the argument is the documented zero value for TIOCSCTTY.
    let result = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as libc::c_ulong, 0) };
    assert_eq!(
        result,
        0,
        "TIOCSCTTY failed: {}",
        io::Error::last_os_error()
    );
}

fn assert_termios_restored(restored: &libc::termios, original: &libc::termios) {
    const MODES: libc::tcflag_t = (libc::ECHO | libc::ICANON | libc::ECHONL | libc::ISIG) as _;
    assert_eq!(
        restored.c_lflag & MODES,
        original.c_lflag & MODES,
        "hidden prompt must restore ECHO/ICANON/ECHONL/ISIG"
    );
    assert_eq!(
        restored.c_cc[libc::VMIN],
        original.c_cc[libc::VMIN],
        "hidden prompt must restore VMIN"
    );
    assert_eq!(
        restored.c_cc[libc::VTIME],
        original.c_cc[libc::VTIME],
        "hidden prompt must restore VTIME"
    );
}

fn tcgetattr(fd: libc::c_int) -> io::Result<libc::termios> {
    let mut term = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: `term` is a valid destination and `fd` is an open descriptor.
    if unsafe { libc::tcgetattr(fd, term.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `tcgetattr` succeeded and initialized the structure.
    Ok(unsafe { term.assume_init() })
}
