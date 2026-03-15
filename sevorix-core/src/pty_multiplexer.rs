//! PTY Multiplexer for shell command interception and validation.
//!
//! This module implements the PTY multiplexer architecture described in the design doc.
//! It provides:
//! - Character-by-character input buffering with immediate echo
//! - Command validation via Watchtower before forwarding to bash
//! - Passthrough mode for interactive programs (vim, less, etc.)
//!
//! # Architecture
//!
//! ```text
//! User Terminal (raw mode)
//!       │
//!       ▼
//! ┌─────────────────┐
//! │  InputBuffer    │ ← Character processing, echo immediately
//! └────────┬────────┘
//!          │ Enter pressed
//!          ▼
//! ┌─────────────────┐
//! │ Watchtower API  │ ← Validate command
//! └────────┬────────┘
//!          │
//!    ┌─────┴─────┐
//!    │           │
//!    ▼           ▼
//! ALLOW       BLOCK
//!    │           │
//!    ▼           ▼
//! Forward to   Show error
//! bash PTY     clear buffer
//! ```

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, ExitStatus};

use nix::sys::termios::{self, LocalFlags, SetArg};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{close, dup2, fork, setsid, ForkResult, Pid};

use crate::input_buffer::{InputAction, InputBuffer, InputBufferError};

/// Errors that can occur during PTY multiplexer operations.
#[derive(Debug)]
pub enum PtyMultiplexerError {
    /// Failed to create PTY
    PtyCreation(io::Error),
    /// Failed to fork process
    ForkFailed(io::Error),
    /// Failed to set terminal attributes
    TerminalAttrs(io::Error),
    /// IO error
    Io(io::Error),
    /// Thread communication error
    ChannelError(String),
    /// Input buffer error
    BufferError(InputBufferError),
    /// Validation error
    ValidationError(String),
}

impl std::fmt::Display for PtyMultiplexerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PtyMultiplexerError::PtyCreation(e) => write!(f, "PTY creation failed: {}", e),
            PtyMultiplexerError::ForkFailed(e) => write!(f, "Fork failed: {}", e),
            PtyMultiplexerError::TerminalAttrs(e) => write!(f, "Terminal attributes error: {}", e),
            PtyMultiplexerError::Io(e) => write!(f, "IO error: {}", e),
            PtyMultiplexerError::ChannelError(s) => write!(f, "Channel error: {}", s),
            PtyMultiplexerError::BufferError(e) => write!(f, "Buffer error: {}", e),
            PtyMultiplexerError::ValidationError(s) => write!(f, "Validation error: {}", s),
        }
    }
}

impl std::error::Error for PtyMultiplexerError {}

impl From<io::Error> for PtyMultiplexerError {
    fn from(e: io::Error) -> Self {
        PtyMultiplexerError::Io(e)
    }
}

impl From<InputBufferError> for PtyMultiplexerError {
    fn from(e: InputBufferError) -> Self {
        PtyMultiplexerError::BufferError(e)
    }
}

/// Verdict from command validation.
#[derive(Debug, Clone)]
pub struct Verdict {
    /// Whether the command is allowed.
    pub allowed: bool,
    /// Status: ALLOW, BLOCK, FLAG.
    pub status: String,
    /// Human-readable reason for the decision.
    pub reason: String,
    /// Confidence level (as string like "99.8%").
    pub confidence: String,
}

impl Default for Verdict {
    fn default() -> Self {
        Self {
            allowed: true,
            status: "ALLOW".to_string(),
            reason: "Default allow".to_string(),
            confidence: "100%".to_string(),
        }
    }
}

/// Configuration for the PTY multiplexer.
#[derive(Debug, Clone)]
pub struct PtyMultiplexerConfig {
    /// Shell executable path.
    pub shell: String,
    /// Environment variables for the shell.
    pub env_vars: Vec<(String, String)>,
    /// Commands that trigger passthrough mode.
    pub passthrough_commands: Vec<String>,
    /// Watchtower URL for validation.
    pub watchtower_url: String,
    /// Timeout for validation requests (ms).
    pub validation_timeout_ms: u64,
}

impl Default for PtyMultiplexerConfig {
    fn default() -> Self {
        Self {
            shell: "/bin/bash".to_string(),
            env_vars: vec![],
            passthrough_commands: vec![
                "vim", "vi", "nvim", "less", "more", "man",
                "top", "htop", "btop", "screen", "tmux",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            watchtower_url: "http://localhost:3000".to_string(),
            validation_timeout_ms: 120_000,
        }
    }
}

/// Operating mode of the multiplexer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiplexerMode {
    /// Normal mode: validate commands before forwarding.
    Validation,
    /// Passthrough mode: bidirectional relay, no validation.
    Passthrough,
}

/// A wrapper around a PTY master file descriptor.
struct PtyMaster {
    fd: RawFd,
}

impl PtyMaster {
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
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let result =
            unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }
}

impl Write for PtyMaster {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let result =
            unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
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
    #[allow(dead_code)]
    slave_name: String,
}

/// Create a PTY pair using POSIX openpty.
fn openpty() -> Result<PtyPair, io::Error> {
    let mut master_fd: libc::c_int = -1;
    let mut slave_fd: libc::c_int = -1;
    let mut slave_name: [libc::c_char; 256] = [0; 256];

    let result = unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            slave_name.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    let slave_name_str = unsafe {
        std::ffi::CStr::from_ptr(slave_name.as_ptr())
            .to_string_lossy()
            .into_owned()
    };

    Ok(PtyPair {
        master: PtyMaster::from_raw_fd(master_fd),
        slave_fd,
        slave_name: slave_name_str,
    })
}

/// Saved terminal state for restoration.
struct SavedTerminal {
    fd: RawFd,
    original_attrs: termios::Termios,
}

impl SavedTerminal {
    /// Save current terminal state and set raw mode.
    fn new(fd: RawFd) -> Result<Self, PtyMultiplexerError> {
        // Wrap the fd in a File for nix functions
        let file = unsafe { File::from_raw_fd(fd) };

        let original_attrs =
            termios::tcgetattr(&file).map_err(|e| PtyMultiplexerError::TerminalAttrs(e.into()))?;

        let mut raw_attrs = original_attrs.clone();
        // Disable canonical mode and echo
        raw_attrs.local_flags &= !(LocalFlags::ICANON | LocalFlags::ECHO);
        // Set VMIN and VTIME using control_chars
        raw_attrs.control_chars[libc::VMIN as usize] = 1;
        raw_attrs.control_chars[libc::VTIME as usize] = 0;

        termios::tcsetattr(&file, SetArg::TCSAFLUSH, &raw_attrs)
            .map_err(|e| PtyMultiplexerError::TerminalAttrs(e.into()))?;

        // Leak the file to prevent it from being closed (we don't own stdin)
        let _ = file.into_raw_fd();

        Ok(Self {
            fd,
            original_attrs,
        })
    }

    /// Restore original terminal state.
    fn restore(&self) -> Result<(), PtyMultiplexerError> {
        let file = unsafe { File::from_raw_fd(self.fd) };
        let result = termios::tcsetattr(&file, SetArg::TCSAFLUSH, &self.original_attrs)
            .map_err(|e| PtyMultiplexerError::TerminalAttrs(e.into()));
        let _ = file.into_raw_fd(); // Don't close stdin
        result
    }
}

impl Drop for SavedTerminal {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// Handle for the bash PTY process.
struct BashPty {
    master: PtyMaster,
    child_pid: Pid,
}

impl BashPty {
    /// Spawn bash in a new PTY.
    fn spawn(shell: &str, env_vars: Vec<(String, String)>) -> Result<Self, PtyMultiplexerError> {
        let pty_pair = openpty().map_err(PtyMultiplexerError::PtyCreation)?;

        match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => {
                // Parent: close slave fd
                let _ = close(pty_pair.slave_fd);

                Ok(Self {
                    master: pty_pair.master,
                    child_pid: child,
                })
            }
            Ok(ForkResult::Child) => {
                // Child: set up PTY slave and exec shell

                // Create new session
                let _ = setsid();

                // Set controlling terminal
                let _ = unsafe { libc::ioctl(pty_pair.slave_fd, libc::TIOCSCTTY, 0) };

                // Dup slave to stdin/stdout/stderr
                let _ = dup2(pty_pair.slave_fd, 0);
                let _ = dup2(pty_pair.slave_fd, 1);
                let _ = dup2(pty_pair.slave_fd, 2);

                // Close fds
                if pty_pair.slave_fd > 2 {
                    let _ = close(pty_pair.slave_fd);
                }
                let master_fd = pty_pair.master.as_raw_fd();
                if master_fd > 2 {
                    let _ = close(master_fd);
                }

                // Build command
                let mut cmd = Command::new(shell);
                cmd.arg("-i").arg("-l"); // Interactive login shell
                for (key, value) in env_vars {
                    cmd.env(key, value);
                }

                // Execute - exec() only returns on error
                let err = cmd.exec();
                eprintln!("Failed to exec {}: {}", shell, err);
                std::process::exit(1);
            }
            Err(e) => Err(PtyMultiplexerError::ForkFailed(e.into())),
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.master.read(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.master.write_all(buf)
    }

    fn is_running(&self) -> bool {
        match waitpid(self.child_pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => true,
            Ok(WaitStatus::Exited(_, _)) => false,
            Ok(WaitStatus::Signaled(_, _, _)) => false,
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

/// Passthrough mode detector.
pub struct PassthroughDetector {
    passthrough_commands: Vec<String>,
}

impl PassthroughDetector {
    /// Create a new detector with the given passthrough commands.
    pub fn new(commands: Vec<String>) -> Self {
        Self {
            passthrough_commands: commands,
        }
    }

    /// Check if a command should trigger passthrough mode.
    pub fn should_enter_passthrough(&self, command: &str) -> bool {
        let cmd_lower = command.to_lowercase();
        let first_word = cmd_lower.split_whitespace().next().unwrap_or("");

        self.passthrough_commands
            .iter()
            .any(|pc| first_word == pc.to_lowercase() || first_word.starts_with(&format!("{} ", pc.to_lowercase())))
    }
}

impl Default for PassthroughDetector {
    fn default() -> Self {
        Self::new(PtyMultiplexerConfig::default().passthrough_commands)
    }
}

/// The PTY multiplexer for command interception and validation.
pub struct PtyMultiplexer {
    /// User terminal (stdin/stdout).
    user_term: SavedTerminal,
    /// Bash PTY.
    bash_pty: BashPty,
    /// Input buffer for character processing.
    input_buffer: InputBuffer,
    /// Passthrough detector.
    passthrough_detector: PassthroughDetector,
    /// Current mode.
    mode: MultiplexerMode,
    /// Watchtower URL for validation.
    watchtower_url: String,
    /// HTTP client for validation.
    client: reqwest::blocking::Client,
    /// Validation timeout in milliseconds.
    validation_timeout_ms: u64,
}

impl PtyMultiplexer {
    /// Create a new PTY multiplexer with the given configuration.
    pub fn new(config: PtyMultiplexerConfig) -> Result<Self, PtyMultiplexerError> {
        // Save and set raw terminal mode for stdin
        let user_term = SavedTerminal::new(libc::STDIN_FILENO)?;

        // Spawn bash in PTY
        let bash_pty = BashPty::spawn(&config.shell, config.env_vars)?;

        // Create passthrough detector
        let passthrough_detector = PassthroughDetector::new(config.passthrough_commands);

        // Create HTTP client for validation
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(config.validation_timeout_ms))
            .build()
            .map_err(|e| PtyMultiplexerError::ValidationError(format!("HTTP client error: {}", e)))?;

        Ok(Self {
            user_term,
            bash_pty,
            input_buffer: InputBuffer::new(),
            passthrough_detector,
            mode: MultiplexerMode::Validation,
            watchtower_url: config.watchtower_url,
            client,
            validation_timeout_ms: config.validation_timeout_ms,
        })
    }

    /// Run the main event loop.
    pub fn run(&mut self) -> Result<ExitStatus, PtyMultiplexerError> {
        let stdin_fd = libc::STDIN_FILENO;
        let bash_fd = self.bash_pty.master.as_raw_fd();

        let mut user_buf = [0u8; 1];
        let mut bash_buf = [0u8; 4096];
        let mut output = Vec::new();

        loop {
            // Use poll to wait for input from either user or bash
            let mut poll_fds = [
                libc::pollfd {
                    fd: stdin_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: bash_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];

            let poll_result =
                unsafe { libc::poll(poll_fds.as_mut_ptr(), 2, -1) };

            if poll_result < 0 {
                let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EINTR {
                    continue;
                }
                return Err(PtyMultiplexerError::Io(io::Error::last_os_error()));
            }

            // Handle user input
            if poll_fds[0].revents & libc::POLLIN != 0 {
                // Read single character from stdin
                let n = match io::stdin().read(&mut user_buf) {
                    Ok(n) => n,
                    Err(e) => {
                        if e.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        return Err(PtyMultiplexerError::Io(e));
                    }
                };

                if n == 0 {
                    // EOF from user
                    break;
                }

                let byte = user_buf[0];

                match self.mode {
                    MultiplexerMode::Validation => {
                        self.handle_validation_input(byte, &mut output)?;
                    }
                    MultiplexerMode::Passthrough => {
                        // Forward directly to bash
                        self.bash_pty.write_all(&[byte])?;
                    }
                }
            }

            // Handle bash output
            if poll_fds[1].revents & libc::POLLIN != 0 {
                let n = match self.bash_pty.read(&mut bash_buf) {
                    Ok(n) => n,
                    Err(e) => {
                        if e.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        return Err(PtyMultiplexerError::Io(e));
                    }
                };

                if n == 0 {
                    // Bash exited
                    break;
                }

                // Forward bash output to user terminal
                io::stdout().write_all(&bash_buf[..n])?;
                io::stdout().flush()?;
            }

            // Check if bash is still running
            if !self.bash_pty.is_running() {
                break;
            }
        }

        // Wait for bash to exit and get status
        loop {
            match waitpid(self.bash_pty.child_pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(_, code)) => {
                    return Ok(ExitStatus::from_raw(code << 8));
                }
                Ok(WaitStatus::Signaled(_, sig, _)) => {
                    return Ok(ExitStatus::from_raw(sig as i32));
                }
                Ok(WaitStatus::StillAlive) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(e) if e == nix::errno::Errno::ECHILD => {
                    return Ok(ExitStatus::from_raw(0));
                }
                Err(_) => {
                    return Ok(ExitStatus::from_raw(1));
                }
                Ok(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
            }
        }
    }

    /// Handle input in validation mode.
    fn handle_validation_input(&mut self, byte: u8, output: &mut Vec<u8>) -> Result<(), PtyMultiplexerError> {
        output.clear();

        // Convert byte to char for InputBuffer
        let c = byte as char;

        // Process character through input buffer
        let action = self.input_buffer.handle_char(c, output)?;

        // Write any echo output to terminal
        if !output.is_empty() {
            io::stdout().write_all(output)?;
            io::stdout().flush()?;
        }

        match action {
            InputAction::ValidateLine(line) => {
                self.handle_line(&line)?;
            }
            InputAction::ForwardToBash(bytes) => {
                // Forward tab/arrow keys to bash
                self.bash_pty.write_all(&bytes)?;
            }
            InputAction::SendSigint => {
                // Ctrl+C: send SIGINT to bash
                let _ = nix::sys::signal::kill(self.bash_pty.child_pid, nix::sys::signal::Signal::SIGINT);
            }
            InputAction::SendEof => {
                // Ctrl+D: send EOF to bash
                self.bash_pty.write_all(&[0x04])?;
            }
            InputAction::NoAction | InputAction::Echo => {
                // Nothing special to do
            }
            InputAction::EnterPassthrough => {
                // Not used in this context
            }
            InputAction::ExitPassthrough => {
                // Not used in this context
            }
        }

        Ok(())
    }

    /// Handle a complete line (Enter was pressed).
    fn handle_line(&mut self, line: &str) -> Result<(), PtyMultiplexerError> {
        let line = line.trim();

        // Empty line - just send newline to bash
        if line.is_empty() {
            self.bash_pty.write_all(b"\n")?;
            return Ok(());
        }

        // Check if this should enter passthrough mode
        if self.passthrough_detector.should_enter_passthrough(line) {
            self.mode = MultiplexerMode::Passthrough;
            // Forward to bash with newline
            self.bash_pty.write_all(line.as_bytes())?;
            self.bash_pty.write_all(b"\n")?;
            return Ok(());
        }

        // Validate with Watchtower
        let verdict = self.validate_command(line)?;

        match verdict.status.as_str() {
            "ALLOW" => {
                // Forward to bash with newline
                self.bash_pty.write_all(line.as_bytes())?;
                self.bash_pty.write_all(b"\n")?;
            }
            "FLAG" => {
                // Show warning, then forward
                eprintln!("\r\n[SEVSH] WARNING: {} (Confidence: {})\r", verdict.reason, verdict.confidence);
                self.bash_pty.write_all(line.as_bytes())?;
                self.bash_pty.write_all(b"\n")?;
            }
            "BLOCK" | _ => {
                // Show error, don't forward
                eprintln!("\r\n[SEVSH] BLOCKED: {}\r", verdict.reason);
            }
        }

        Ok(())
    }

    /// Validate a command with Watchtower.
    fn validate_command(&self, cmd: &str) -> Result<Verdict, PtyMultiplexerError> {
        let url = format!("{}/analyze", self.watchtower_url);

        let body = serde_json::json!({
            "payload": cmd,
            "agent": "sevsh-pty",
            "context": "Shell"
        });

        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .map_err(|e| {
                PtyMultiplexerError::ValidationError(format!("Watchtower request failed: {}", e))
            })?;

        if !response.status().is_success() {
            // Fail closed on HTTP errors
            return Ok(Verdict {
                allowed: false,
                status: "ERROR".to_string(),
                reason: format!("API Error: {}", response.status()),
                confidence: "100%".to_string(),
            });
        }

        let json: serde_json::Value = response.json().map_err(|e| {
            PtyMultiplexerError::ValidationError(format!("Failed to parse response: {}", e))
        })?;

        let status = json["status"]
            .as_str()
            .unwrap_or("UNKNOWN")
            .to_string();
        let reason = json["reason"]
            .as_str()
            .unwrap_or("Policy violation")
            .to_string();
        let confidence = json["confidence"]
            .as_str()
            .unwrap_or("Unknown")
            .to_string();

        let allowed = status == "ALLOW" || status == "FLAG";

        Ok(Verdict {
            allowed,
            status,
            reason,
            confidence,
        })
    }

    /// Get the current mode.
    pub fn mode(&self) -> MultiplexerMode {
        self.mode
    }

    /// Enter passthrough mode (for testing).
    pub fn enter_passthrough(&mut self) {
        self.mode = MultiplexerMode::Passthrough;
    }

    /// Exit passthrough mode (for testing).
    pub fn exit_passthrough(&mut self) {
        self.mode = MultiplexerMode::Validation;
    }
}

impl Drop for PtyMultiplexer {
    fn drop(&mut self) {
        // Restore terminal settings
        let _ = self.user_term.restore();

        // Kill bash if still running
        if self.bash_pty.is_running() {
            let _ = nix::sys::signal::kill(
                self.bash_pty.child_pid,
                nix::sys::signal::Signal::SIGTERM,
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
            if self.bash_pty.is_running() {
                let _ = nix::sys::signal::kill(
                    self.bash_pty.child_pid,
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passthrough_detector() {
        let detector = PassthroughDetector::default();

        assert!(detector.should_enter_passthrough("vim"));
        assert!(detector.should_enter_passthrough("vim file.txt"));
        assert!(detector.should_enter_passthrough("less /var/log/syslog"));
        assert!(detector.should_enter_passthrough("man bash"));
        assert!(detector.should_enter_passthrough("top"));

        assert!(!detector.should_enter_passthrough("ls -la"));
        assert!(!detector.should_enter_passthrough("echo hello"));
        assert!(!detector.should_enter_passthrough("cat file.txt"));
    }

    #[test]
    fn test_passthrough_detector_case_insensitive() {
        let detector = PassthroughDetector::default();

        assert!(detector.should_enter_passthrough("VIM"));
        assert!(detector.should_enter_passthrough("Less"));
        assert!(detector.should_enter_passthrough("TOP"));
    }

    #[test]
    fn test_verdict_default() {
        let verdict = Verdict::default();
        assert!(verdict.allowed);
        assert_eq!(verdict.status, "ALLOW");
    }

    #[test]
    fn test_multiplexer_config_default() {
        let config = PtyMultiplexerConfig::default();
        assert_eq!(config.shell, "/bin/bash");
        assert!(!config.passthrough_commands.is_empty());
        assert_eq!(config.watchtower_url, "http://localhost:3000");
    }

    #[test]
    fn test_multiplexer_mode_equality() {
        assert_eq!(MultiplexerMode::Validation, MultiplexerMode::Validation);
        assert_eq!(MultiplexerMode::Passthrough, MultiplexerMode::Passthrough);
        assert_ne!(MultiplexerMode::Validation, MultiplexerMode::Passthrough);
    }
}