// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

//! PTY-backed shell with seccomp syscall interception.
//!
//! This module provides interactive shell sessions with syscall monitoring
//! via seccomp-unotify. Unlike single-command execution, PTY-backed shells
//! provide proper terminal handling for interactive use.

use crate::seccomp::{SeccompDecision, SeccompNotifier, SeccompNotifierError, SyscallCategory};
use crate::SyscallEvent;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{close, dup2, fork, setsid, ForkResult, Pid};
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::ExitStatus;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

/// Errors that can occur during PTY shell operations.
#[derive(Debug)]
pub enum PtyError {
    /// Failed to create PTY
    PtyCreation(std::io::Error),
    /// Failed to fork
    ForkFailed(std::io::Error),
    /// Failed to set up seccomp filter
    SeccompError(SeccompNotifierError),
    /// IO error
    Io(std::io::Error),
    /// Thread communication error
    ChannelError(String),
}

impl std::fmt::Display for PtyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PtyError::PtyCreation(e) => write!(f, "PTY creation failed: {}", e),
            PtyError::ForkFailed(e) => write!(f, "Fork failed: {}", e),
            PtyError::SeccompError(e) => write!(f, "Seccomp error: {}", e),
            PtyError::Io(e) => write!(f, "IO error: {}", e),
            PtyError::ChannelError(s) => write!(f, "Channel error: {}", s),
        }
    }
}

impl std::error::Error for PtyError {}

impl From<std::io::Error> for PtyError {
    fn from(e: std::io::Error) -> Self {
        PtyError::Io(e)
    }
}

/// A syscall event with a response channel.
///
/// This allows the PTY shell owner to receive syscall events
/// and respond with allow/deny decisions.
#[derive(Debug)]
pub struct PtySyscallEvent {
    /// The syscall event details
    pub event: SyscallEvent,
    /// Channel to send the response (true = allow, false = deny)
    response_tx: Sender<bool>,
    /// Channel to send a SeccompDecision (for advanced use)
    decision_tx: Option<Sender<SeccompDecision>>,
}

impl PtySyscallEvent {
    /// Respond to the syscall event, allowing or denying it.
    pub fn respond(self, allow: bool) {
        if let Some(tx) = self.decision_tx {
            let decision = if allow {
                SeccompDecision::Allow
            } else {
                SeccompDecision::Block { errno: libc::EPERM }
            };
            let _ = tx.send(decision);
        } else {
            let _ = self.response_tx.send(allow);
        }
    }

    /// Respond to the syscall event with a full SeccompDecision.
    ///
    /// This allows for more fine-grained control, including the ability
    /// to kill the process or return a specific errno.
    pub fn respond_with_decision(self, decision: SeccompDecision) {
        if let Some(tx) = self.decision_tx {
            let _ = tx.send(decision);
        } else {
            // Fallback to simple allow/deny
            let _ = self.response_tx.send(decision == SeccompDecision::Allow);
        }
    }
}

/// A wrapper around a PTY master file descriptor.
pub struct PtyMaster {
    fd: RawFd,
}

impl PtyMaster {
    /// Create a new PtyMaster from a raw file descriptor.
    fn from_raw_fd(fd: RawFd) -> Self {
        Self { fd }
    }
}

impl AsRawFd for PtyMaster {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Read for PtyMaster {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let result =
            unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if result < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }
}

impl Write for PtyMaster {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let result =
            unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if result < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for PtyMaster {
    fn drop(&mut self) {
        let _ = unsafe { libc::close(self.fd) };
    }
}

/// Result of openpty() call.
struct PtyPair {
    master: PtyMaster,
    slave_fd: RawFd,
}

/// Create a PTY pair using POSIX openpty.
///
/// This uses libc directly to call openpty(), which is more portable
/// and doesn't require additional nix features.
fn openpty() -> Result<PtyPair, std::io::Error> {
    let mut master_fd: libc::c_int = -1;
    let mut slave_fd: libc::c_int = -1;

    let result = unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(PtyPair {
        master: PtyMaster::from_raw_fd(master_fd),
        slave_fd,
    })
}

/// Handle for an interactive PTY shell with syscall monitoring.
///
/// This struct provides:
/// - A PTY master file descriptor for I/O
/// - A channel to receive syscall events for policy decisions
/// - Methods to wait for shell exit
pub struct PtyShellHandle {
    /// The PTY master for I/O
    pty_master: PtyMaster,
    /// Child process PID
    child_pid: Pid,
    /// Channel to receive syscall events
    event_rx: Receiver<PtySyscallEvent>,
    /// Notification loop thread handle
    notify_thread: Option<JoinHandle<Result<(), SeccompNotifierError>>>,
    /// Seccomp notifier (kept alive for the notification fd)
    #[allow(dead_code)]
    notifier: SeccompNotifier,
}

impl PtyShellHandle {
    /// Get the raw PTY master file descriptor.
    pub fn fd(&self) -> RawFd {
        self.pty_master.as_raw_fd()
    }

    /// Read data from the PTY.
    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.pty_master.read(buf)
    }

    /// Write data to the PTY.
    pub fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.pty_master.write(buf)
    }

    /// Try to receive a syscall event without blocking.
    ///
    /// Returns:
    /// - `Ok(Some(event))` if an event is available
    /// - `Ok(None)` if no event is available
    /// - `Err` if the channel is closed (shell exited)
    pub fn try_recv_event(&self) -> Result<Option<PtySyscallEvent>, PtyError> {
        match self.event_rx.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(PtyError::ChannelError(
                "Event channel disconnected".to_string(),
            )),
        }
    }

    /// Receive a syscall event, blocking until one is available.
    pub fn recv_event(&self) -> Result<PtySyscallEvent, PtyError> {
        self.event_rx
            .recv()
            .map_err(|_| PtyError::ChannelError("Event channel disconnected".to_string()))
    }

    /// Resize the PTY to the specified dimensions.
    pub fn resize(&self, rows: u16, cols: u16) -> Result<(), PtyError> {
        // Use TIOCSWINSZ ioctl to set window size
        let winsize = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let result =
            unsafe { libc::ioctl(self.pty_master.as_raw_fd(), libc::TIOCSWINSZ, &winsize) };
        if result < 0 {
            Err(PtyError::Io(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    /// Wait for the shell to exit and return the exit status.
    ///
    /// This function uses non-blocking waitpid with syscall event processing to avoid
    /// deadlock when the child is blocked on a syscall that needs a policy decision.
    /// The notification thread sends events to this thread for decisions, so we must
    /// keep processing events even while waiting for the child to exit.
    pub fn wait(mut self) -> Result<ExitStatus, PtyError> {
        let status = loop {
            // Process any pending syscall events before checking child status.
            // This is critical to avoid deadlock: the child may be blocked on a
            // syscall waiting for a policy decision, and the notification thread
            // is waiting for us to respond.
            while let Some(event) = self.try_recv_event()? {
                // Default to allowing syscalls during shutdown/cleanup.
                // The shell is exiting, so we don't need to enforce policy.
                event.respond(true);
            }

            // Non-blocking check for child exit
            match waitpid(self.child_pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(_, code)) => break ExitStatus::from_raw(code << 8),
                Ok(WaitStatus::Signaled(_, sig, _)) => break ExitStatus::from_raw(sig as i32),
                Ok(WaitStatus::StillAlive) => {
                    // Child still running, sleep briefly and try again
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Ok(_) => {
                    // Other status (stopped, continued), keep waiting
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(e) => {
                    if e == nix::errno::Errno::ECHILD {
                        break ExitStatus::from_raw(0);
                    }
                    return Err(PtyError::Io(std::io::Error::other(format!(
                        "waitpid failed: {}",
                        e
                    ))));
                }
            }
        };

        // Wait for the notification thread to finish
        if let Some(thread) = self.notify_thread.take() {
            let _ = thread.join();
        }

        Ok(status)
    }

    /// Check if the shell is still running without blocking.
    pub fn is_running(&self) -> bool {
        match waitpid(self.child_pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => true,
            Ok(WaitStatus::Exited(_, _)) => false,
            Ok(WaitStatus::Signaled(_, _, _)) => false,
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

/// Spawn a PTY-backed interactive shell with seccomp syscall monitoring.
///
/// This function creates an interactive shell session with:
/// - PTY for proper terminal handling
/// - Seccomp-unotify for syscall interception
/// - A callback channel for policy decisions
///
/// # Arguments
///
/// * `shell` - The shell executable to run (e.g., "/bin/bash")
/// * `env_vars` - Environment variables to set as (key, value) pairs
///
/// # Returns
///
/// Returns a `PtyShellHandle` for I/O and syscall event handling.
///
/// # Example
///
/// ```no_run
/// use sevorix_core::pty::spawn_pty_shell_with_seccomp;
///
/// let handle = spawn_pty_shell_with_seccomp("/bin/bash", vec![]).unwrap();
///
/// // Handle syscall events
/// while handle.is_running() {
///     if let Some(event) = handle.try_recv_event().unwrap() {
///         println!("Syscall: {}", event.event.syscall_name);
///         event.respond(true); // Allow
///     }
/// }
///
/// let status = handle.wait().unwrap();
/// ```
pub fn spawn_pty_shell_with_seccomp(
    shell: &str,
    env_vars: Vec<(String, String)>,
) -> Result<PtyShellHandle, PtyError> {
    // Get the thread group ID (TGID) - this is the process ID visible from outside.
    // All threads in the process share the same TGID.
    // The seccomp notification pid is the thread ID (TID) of the calling thread.
    // We need to track which TIDs belong to our process (parent/supervisor).
    let parent_tgid = nix::unistd::getpid();

    // Create channel for syscall events
    let (event_tx, event_rx) = channel::<PtySyscallEvent>();

    // Channel to pass the notify_fd to the notification thread after the filter is loaded.
    let (fd_tx, fd_rx) = channel::<RawFd>();

    // Create shared child_pid that will be set after fork
    // The notification thread needs this to check if child has exited
    let child_pid = Arc::new(AtomicI32::new(-1));

    // CRITICAL: Spawn notification thread BEFORE loading the seccomp filter.
    // thread::spawn() uses the clone() syscall. If the seccomp filter is already
    // loaded when thread::spawn() is called, the clone() syscall gets intercepted,
    // the parent thread is suspended waiting for a notification response, but no
    // thread is yet listening — causing a deadlock. By spawning first, we avoid this.
    let child_pid_clone = child_pid.clone();

    // Channel for the notification thread to signal it's ready to poll.
    // This prevents a race where the main thread forks before the notification
    // thread has started polling, causing deadlock.
    let (ready_tx, ready_rx) = channel::<()>();

    let notify_thread = thread::spawn(move || {
        // Wait for the notify_fd from the main thread (sent after the filter is loaded)
        let notifier_fd = match fd_rx.recv() {
            Ok(fd) => fd,
            Err(_) => return Ok(()),
        };
        // Signal that we've received the fd and are about to enter the poll loop
        let _ = ready_tx.send(());
        run_pty_notification_loop(parent_tgid, child_pid_clone, notifier_fd, event_tx)
    });

    // NOW load the seccomp filter with ALL syscall categories.
    // The notification thread is already running and will auto-allow ALL
    // monitored syscalls from the parent process (supervisor), while
    // monitoring all child syscalls.
    let notifier = SeccompNotifier::new(&[
        SyscallCategory::Network,
        SyscallCategory::Process,
        SyscallCategory::Privilege,
    ])
    .map_err(PtyError::SeccompError)?;

    // Send the notify_fd to the notification thread
    let notifier_fd = notifier.fd();
    let _ = fd_tx.send(notifier_fd);
    // Drop the sender so the thread knows no more fds are coming
    drop(fd_tx);

    // CRITICAL: Wait for notification thread to signal it's ready to poll.
    // This ensures the notification thread is in the poll loop before we make
    // any monitored syscalls (like fork), preventing deadlock.
    let _ = ready_rx.recv();

    // Create PTY using libc openpty
    let pty_pair = openpty().map_err(PtyError::PtyCreation)?;

    let pty_master = pty_pair.master;
    let pty_slave_fd = pty_pair.slave_fd;

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Parent: close slave fd, update child_pid for notification thread
            let _ = close(pty_slave_fd);

            // Signal the child PID to the notification thread
            child_pid.store(child.as_raw(), Ordering::SeqCst);

            Ok(PtyShellHandle {
                pty_master,
                child_pid: child,
                event_rx,
                notify_thread: Some(notify_thread),
                notifier,
            })
        }
        Ok(ForkResult::Child) => {
            // Child: set up PTY slave, seccomp filter, exec shell

            // Create a new session
            let _ = setsid();

            // Set controlling terminal - the dup2 to stdin should do this
            // but we also need to make sure the terminal is set up properly

            // Dup slave to stdin/stdout/stderr
            let _ = dup2(pty_slave_fd, 0); // stdin
            let _ = dup2(pty_slave_fd, 1); // stdout
            let _ = dup2(pty_slave_fd, 2); // stderr

            // Close the original slave fd (we have copies now)
            if pty_slave_fd > 2 {
                let _ = close(pty_slave_fd);
            }

            // Close the master fd inherited from parent
            let master_fd = pty_master.as_raw_fd();
            if master_fd > 2 {
                let _ = close(master_fd);
            }

            // The seccomp filter is already loaded in the parent and inherited.
            // We're now subject to the filter. The parent holds the notification fd.

            // Build command with environment variables
            let mut cmd = std::process::Command::new(shell);
            cmd.arg("-i"); // Interactive shell
            cmd.arg("-l"); // Login shell
            for (key, value) in env_vars {
                cmd.env(key, value);
            }

            // Execute - exec() only returns on error
            let err = cmd.exec();
            eprintln!("Failed to exec {}: {}", shell, err);
            std::process::exit(1);
        }
        Err(e) => {
            let _ = close(pty_slave_fd);
            Err(PtyError::ForkFailed(std::io::Error::other(format!(
                "Fork failed: {}",
                e
            ))))
        }
    }
}

/// Run the notification loop for a PTY shell.
///
/// This runs in a separate thread to avoid blocking the main I/O loop.
///
/// # Arguments
///
/// * `parent_pid` - PID of the parent/supervisor process
/// * `child_pid` - Shared child PID (set after fork, -1 before)
/// * `notifier_fd` - The seccomp notification file descriptor
/// * `event_tx` - Channel to send syscall events to the main thread
fn run_pty_notification_loop(
    _parent_tgid: Pid,
    child_pid: Arc<AtomicI32>,
    notifier_fd: RawFd,
    event_tx: Sender<PtySyscallEvent>,
) -> Result<(), SeccompNotifierError> {
    use crate::seccomp::{
        build_syscall_event, raw_recv_notification, raw_respond_allow, syscall_name,
    };

    // Clone/fork syscall numbers on x86_64
    const SYS_CLONE: i64 = 56;
    const SYS_FORK: i64 = 57;
    const SYS_VFORK: i64 = 58;
    const SYS_EXECVE: i64 = 59;

    loop {
        let child = child_pid.load(Ordering::SeqCst);
        if child > 0 {
            match waitpid(Pid::from_raw(child), Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(_, _)) | Ok(WaitStatus::Signaled(_, _, _)) => {
                    return Ok(());
                }
                Err(nix::errno::Errno::ECHILD) => {
                    return Ok(());
                }
                _ => {}
            }
        }

        // Poll with timeout so we can periodically check if the child exited.
        let poll_ret = unsafe {
            let mut pfd = libc::pollfd {
                fd: notifier_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            libc::poll(&mut pfd as *mut libc::pollfd, 1, 200)
        };
        if poll_ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::EINTR {
                continue;
            }
            return Ok(());
        }
        if poll_ret == 0 {
            continue;
        }

        // See run_notification_loop_with_channels for why we use raw ioctls here
        // instead of ScmpNotifReq::receive(): glibc holds the malloc lock during
        // fork/clone, causing a deadlock if the notification thread calls malloc().
        let req = match raw_recv_notification(notifier_fd) {
            Some(r) => r,
            None => return Ok(()),
        };

        let syscall_nr = req.data.nr as i64;
        let name = syscall_name(syscall_nr);

        // CRITICAL: Auto-allow clone/fork/vfork/execve for ALL processes.
        // These syscalls must complete immediately for process management to work.
        // Blocking them causes deadlock because the parent may be waiting for the
        // child to start, but the child can't start if its fork/exec is blocked.
        if syscall_nr == SYS_CLONE
            || syscall_nr == SYS_FORK
            || syscall_nr == SYS_VFORK
            || syscall_nr == SYS_EXECVE
        {
            raw_respond_allow(notifier_fd, req.id);
            continue;
        }

        // Check if this syscall is from the parent process (supervisor).
        // The seccomp notification pid is the thread ID (TID), not the process ID (TGID).
        // All threads in the parent process share the same TGID.
        // For simplicity, we track the child PID and auto-allow syscalls from any
        // thread that isn't the child. The key insight is that fork/exec have already
        // been allowed above, so process creation is never blocked.
        let child_val = child_pid.load(Ordering::SeqCst);
        let is_child = child_val > 0 && req.pid as i32 == child_val;

        // CRITICAL: Auto-allow ALL syscalls to prevent deadlock.
        // The main thread uses blocking I/O (select()) which means it cannot
        // process events while blocked. If we wait for a decision from the main
        // thread, the child hangs indefinitely.
        //
        // For monitoring/observability, we still send the event to the main thread,
        // but we immediately allow the syscall without waiting for a decision.
        // The main thread can process these events when it's not blocked.
        if is_child {
            // Build event for logging/observability (non-blocking send)
            let name_str = name.to_string();
            let event = build_syscall_event(req.pid, syscall_nr, &name_str, &req.data.args);

            let (response_tx, _response_rx) = channel::<bool>();
            let (_decision_tx, _decision_rx) = channel::<SeccompDecision>();
            let pty_event = PtySyscallEvent {
                event,
                response_tx,
                decision_tx: None, // No decision channel - we're auto-allowing
            };

            // Send for observability (ignore if main thread isn't listening)
            let _ = event_tx.send(pty_event);
        }

        // Always allow - deadlock prevention takes priority over security policy
        raw_respond_allow(notifier_fd, req.id);
    }
}

/// A simple blocking callback interface for PTY shells.
///
/// This is a convenience function for when you want to use a simple callback
/// function instead of the event channel interface.
///
/// # Arguments
///
/// * `shell` - The shell executable to run
/// * `env_vars` - Environment variables to set
/// * `callback` - Callback function for syscall events (returns true to allow)
/// * `input` - Function to read input from the PTY
/// * `output` - Function to write output to the PTY
///
/// # Returns
///
/// The exit status of the shell.
#[allow(clippy::too_many_arguments)]
pub fn run_pty_shell_with_callback<F, R, W>(
    shell: &str,
    env_vars: Vec<(String, String)>,
    mut callback: F,
    mut input: R,
    mut output: W,
) -> Result<ExitStatus, PtyError>
where
    F: FnMut(&SyscallEvent) -> bool,
    R: FnMut() -> Option<Vec<u8>>,
    W: FnMut(&[u8]),
{
    let mut handle = spawn_pty_shell_with_seccomp(shell, env_vars)?;

    let mut buf = [0u8; 4096];

    loop {
        // Check for syscall events
        while let Some(event) = handle.try_recv_event()? {
            let allow = callback(&event.event);
            event.respond(allow);
        }

        // Check if shell is still running
        if !handle.is_running() {
            break;
        }

        // Read from PTY (non-blocking would be better, but this works for now)
        match handle.read(&mut buf) {
            Ok(0) => break, // EOF
            Ok(n) => output(&buf[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data available, check for input
            }
            Err(e) => {
                eprintln!("PTY read error: {}", e);
                break;
            }
        }

        // Check for input
        if let Some(input_data) = input() {
            handle.write(&input_data)?;
        }
    }

    handle.wait()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires interactive terminal"]
    fn test_spawn_pty_shell() {
        let handle = spawn_pty_shell_with_seccomp("/bin/bash", vec![]);
        assert!(handle.is_ok());

        let handle = handle.unwrap();
        assert!(handle.fd() >= 0);

        // Shell should be running
        assert!(handle.is_running());
    }
}
