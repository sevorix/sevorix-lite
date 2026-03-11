# PTY Multiplexer Architecture Design

## Overview

The PTY Multiplexer provides shell command interception with full terminal semantics while maintaining interactivity and enabling validation of complete commands before execution.

## Problem Statement

Current `sevsh` uses a rustyline-based REPL which:
- Lacks full terminal emulation (no vim/less support)
- Validates commands but doesn't provide a real shell experience
- Cannot handle interactive programs

The existing PTY shell (`pty.rs`) uses seccomp-unotify which:
- Auto-allows all syscalls due to deadlock concerns
- Provides observability only, not enforcement
- Cannot validate commands before execution

**Solution:** A PTY multiplexer that buffers user input, validates complete commands on Enter, and forwards allowed commands to a bash PTY.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER TERMINAL                                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SEVSH PTY MULTIPLEXER                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         Input PTY (Master)                             │  │
│  │   - User connects here                                                 │  │
│  │   - sevsh owns the master fd                                           │  │
│  │   - Raw mode enabled for character-by-character input                  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                      │                                       │
│                                      ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         INPUT HANDLER                                  │  │
│  │   ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐   │  │
│  │   │   Char      │  │   Line      │  │      Command Buffer         │   │  │
│  │   │   Receiver  │──│   Buffer    │──│   (accumulates until Enter) │   │  │
│  │   └─────────────┘  └─────────────┘  └─────────────────────────────┘   │  │
│  │                                                                       │  │
│  │   Echo Path: User char ──► Input PTY echo (immediate)                │  │
│  │   Valid Path: Enter ──► Watchtower validation ──► Allow/Deny         │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                      │                                       │
│                        ┌─────────────┴─────────────┐                        │
│                        │                           │                        │
│                        ▼                           ▼                        │
│              ┌─────────────────┐         ┌─────────────────┐               │
│              │  ALLOW PATH     │         │   DENY PATH     │               │
│              │                 │         │                 │               │
│              │ Forward line    │         │ Show error      │               │
│              │ to bash PTY     │         │ Don't forward   │               │
│              └────────┬────────┘         └─────────────────┘               │
│                       │                                                     │
└───────────────────────┼─────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           OUTPUT PTY (Master)                                │
│   - Bash runs as slave                                                      │
│   - sevsh reads bash output                                                 │
│   - Output forwarded to user terminal                                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              BASH PROCESS                                    │
│   - Runs in its own PTY (slave)                                             │
│   - Full terminal semantics (vim, less, etc. work)                          │
│   - Network sandboxed (existing sevsh feature)                              │
│   - eBPF daemon monitors syscalls (observability)                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Input PTY (User-Facing)

**Purpose:** Provides the user interface terminal.

**Configuration:**
- Raw mode (termios) for character-by-character input
- Echo enabled (sevsh echoes immediately for responsiveness)
- Signal handling (SIGINT, SIGQUIT passed through)

**Key Operations:**
```rust
struct InputPty {
    master_fd: RawFd,
    termios_original: termios,  // Saved for restoration
}

impl InputPty {
    fn new() -> Result<Self, PtyError>;
    fn set_raw_mode(&mut self) -> Result<(), PtyError>;
    fn read_char(&mut self) -> Result<Option<u8>, PtyError>;
    fn write(&mut self, data: &[u8]) -> Result<(), PtyError>;
    fn restore_terminal(&mut self) -> Result<(), PtyError>;
}
```

### 2. Output PTY (Bash-Facing)

**Purpose:** Runs bash with full terminal semantics.

**Configuration:**
- Bash spawned as slave with `-i` (interactive) and `-l` (login)
- Environment includes proxy settings for HTTP layer integration
- Window size synced from input PTY

**Key Operations:**
```rust
struct OutputPty {
    master_fd: RawFd,
    child_pid: Pid,
    slave_name: String,
}

impl OutputPty {
    fn new(shell: &str, env_vars: Vec<(String, String)>) -> Result<Self, PtyError>;
    fn write(&mut self, data: &[u8]) -> Result<(), PtyError>;
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, PtyError>;
    fn resize(&self, rows: u16, cols: u16) -> Result<(), PtyError>;
    fn wait(&mut self) -> Result<ExitStatus, PtyError>;
    fn is_running(&self) -> bool;
}
```

### 3. Command Buffer

**Purpose:** Accumulates characters until Enter, handling line editing.

**Features:**
- Backspace support
- Ctrl+C interrupt (clears buffer, not passed to bash)
- Ctrl+D EOF handling
- Tab completion passthrough (sent to bash for completion)

**State:**
```rust
struct CommandBuffer {
    buffer: Vec<u8>,
    cursor_pos: usize,
    in_escape: bool,        // Track ANSI escape sequences
    escape_buffer: Vec<u8>,
}

impl CommandBuffer {
    fn push_char(&mut self, c: u8);
    fn backspace(&mut self);
    fn clear(&mut self);
    fn get_line(&self) -> &[u8];
    fn is_complete(&self) -> bool;  // True when Enter pressed
}
```

### 4. Passthrough Mode Detector

**Purpose:** Detect when to switch from validation mode to raw passthrough.

**Triggers for Passthrough:**
- `vim`, `vi`, `nvim` commands
- `less`, `more` commands
- `man` command
- `top`, `htop`, `btop` commands
- `screen`, `tmux` commands
- Any command in configured passthrough list

**Implementation:**
```rust
struct PassthroughDetector {
    passthrough_commands: Vec<String>,
}

impl PassthroughDetector {
    fn is_passthrough(&self, command: &str) -> bool;
    fn should_enter_passthrough(&self, command: &str) -> bool;
}
```

## State Machine for Input Handling

```
                         ┌──────────────────────────────┐
                         │                              │
                         ▼                              │
┌────────────┐     ┌────────────┐     ┌────────────┐   │
│   INIT     │────►│  IDLE      │────►│  RECEIVING │   │
└────────────┘     └────────────┘     └─────┬──────┘   │
                         │                   │          │
                         │                   │          │
                         │           Char received      │
                         │           (non-Enter)        │
                         │                   │          │
                         │                   ▼          │
                         │           ┌────────────┐     │
                         │           │  BUFFER    │     │
                         │           │  Echo char │     │
                         │           └─────┬──────┘     │
                         │                 │            │
                         │                 │ Enter      │
                         │                 │ received   │
                         │                 ▼            │
                         │           ┌────────────┐     │
                         │           │  VALIDATE  │     │
                         │           │  Query     │     │
                         │           │  Watchtower│     │
                         │           └─────┬──────┘     │
                         │                 │            │
                         │        ┌────────┴────────┐   │
                         │        │                 │   │
                         │        ▼                 ▼   │
                         │  ┌────────────┐   ┌────────────┐
                         │  │  ALLOWED   │   │  DENIED    │
                         │  │  Forward   │   │  Show error│
                         │  │  to bash   │   │  Clear buf │
                         │  └─────┬──────┘   └─────┬──────┘
                         │        │                │
                         │        │                │
                         │        └────────┬───────┘
                         │                 │
                         │                 ▼
                         │           ┌────────────┐
                         └───────────│  IDLE      │
                                     └────────────┘

                    PASSTHROUGH MODE
                    ================

┌────────────┐     ┌────────────┐     ┌────────────┐
│  IDLE      │────►│ PASSTHROUGH│────►│  IDLE      │
└────────────┘     │   MODE     │     └────────────┘
  (detected        └────────────┘       (process
   passthrough           │               exits)
   command)              │
                    Bidirectional
                    forwarding
                    (no validation)
```

### State Transitions

| Current State | Event | Next State | Action |
|--------------|-------|------------|--------|
| INIT | PTYs created | IDLE | Ready for input |
| IDLE | Char received | RECEIVING | Buffer char, echo |
| RECEIVING | Char received | RECEIVING | Buffer char, echo |
| RECEIVING | Enter received | VALIDATE | Send to Watchtower |
| RECEIVING | Ctrl+C | IDLE | Clear buffer, show ^C |
| RECEIVING | Ctrl+D | IDLE | Send EOF to bash if buffer empty |
| RECEIVING | Tab | RECEIVING | Forward to bash for completion |
| VALIDATE | ALLOW response | ALLOWED | Forward line to bash |
| VALIDATE | DENY response | DENIED | Show error, clear buffer |
| ALLOWED | Command sent | IDLE | Wait for next input |
| DENIED | Error shown | IDLE | Wait for next input |
| IDLE | Passthrough command detected | PASSTHROUGH | Enable bidirectional relay |
| PASSTHROUGH | Child exits | IDLE | Return to validation mode |

## Interface Definitions

### Core Traits

```rust
/// Trait for PTY operations.
pub trait Pty: Read + Write {
    /// Get the raw file descriptor.
    fn fd(&self) -> RawFd;

    /// Resize the PTY window.
    fn resize(&self, rows: u16, cols: u16) -> Result<(), PtyError>;

    /// Check if the associated process is running.
    fn is_running(&self) -> bool;
}

/// Trait for command validation.
pub trait CommandValidator {
    /// Validate a command string.
    /// Returns the validation verdict.
    fn validate(&self, command: &str) -> impl Future<Output = Result<Verdict, ValidationError>>;
}

/// Trait for passthrough detection.
pub trait PassthroughDetector {
    /// Check if a command should trigger passthrough mode.
    fn should_passthrough(&self, command: &str) -> bool;
}

/// Trait for input processing.
pub trait InputProcessor {
    /// Process a single character.
    /// Returns true if the line is complete (Enter was pressed).
    fn process_char(&mut self, c: u8) -> Result<InputAction, InputError>;

    /// Get the current line buffer.
    fn current_line(&self) -> &str;

    /// Clear the line buffer.
    fn clear(&mut self);
}

/// Actions resulting from input processing.
#[derive(Debug, Clone)]
pub enum InputAction {
    /// Echo the character to the terminal.
    Echo(u8),
    /// Line is complete, validate it.
    LineComplete(String),
    /// Forward to bash (for tab completion).
    ForwardToBash(Vec<u8>),
    /// Clear the line (Ctrl+C).
    ClearLine,
    /// Send EOF to bash (Ctrl+D with empty buffer).
    SendEof,
    /// Ignore the character.
    Ignore,
}
```

### Multiplexer Interface

```rust
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
    /// Enable network sandbox.
    pub enable_sandbox: bool,
}

impl Default for PtyMultiplexerConfig {
    fn default() -> Self {
        Self {
            shell: "/bin/bash".to_string(),
            env_vars: vec![],
            passthrough_commands: vec![
                "vim", "vi", "nvim", "less", "more", "man",
                "top", "htop", "btop", "screen", "tmux",
            ].iter().map(|s| s.to_string()).collect(),
            watchtower_url: "http://localhost:3000".to_string(),
            validation_timeout_ms: 5000,
            enable_sandbox: true,
        }
    }
}

/// The main PTY multiplexer.
pub struct PtyMultiplexer {
    /// Input PTY (user-facing).
    input_pty: InputPty,
    /// Output PTY (bash-facing).
    output_pty: OutputPty,
    /// Command buffer.
    buffer: CommandBuffer,
    /// Passthrough detector.
    passthrough_detector: SimplePassthroughDetector,
    /// Current mode.
    mode: MultiplexerMode,
    /// Watchtower client.
    validator: WatchtowerValidator,
}

/// Operating mode of the multiplexer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiplexerMode {
    /// Normal mode: validate commands before forwarding.
    Validation,
    /// Passthrough mode: bidirectional relay, no validation.
    Passthrough,
}

impl PtyMultiplexer {
    /// Create a new PTY multiplexer.
    pub fn new(config: PtyMultiplexerConfig) -> Result<Self, PtyError>;

    /// Run the main event loop.
    pub fn run(&mut self) -> Result<ExitStatus, PtyError>;

    /// Handle a single character of input.
    fn handle_input_char(&mut self, c: u8) -> Result<InputAction, PtyError>;

    /// Validate and handle a complete line.
    async fn handle_line(&mut self, line: &str) -> Result<(), PtyError>;

    /// Enter passthrough mode.
    fn enter_passthrough(&mut self);

    /// Exit passthrough mode.
    fn exit_passthrough(&mut self);

    /// Relay data bidirectionally (for passthrough mode).
    fn relay_bidirectional(&mut self) -> Result<(), PtyError>;
}
```

### Validation Response

```rust
/// Verdict from command validation.
#[derive(Debug, Clone)]
pub struct Verdict {
    /// Whether the command is allowed.
    pub allowed: bool,
    /// Status: ALLOW, BLOCK, FLAG.
    pub status: String,
    /// Human-readable reason for the decision.
    pub reason: String,
    /// Confidence level (0.0 - 1.0).
    pub confidence: f32,
}

/// Error during validation.
#[derive(Debug, Clone)]
pub enum ValidationError {
    /// Watchtower is unreachable.
    Unreachable(String),
    /// Invalid response from Watchtower.
    InvalidResponse(String),
    /// Validation timed out.
    Timeout,
    /// Internal error.
    Internal(String),
}
```

## Error Handling Strategy

### Error Categories

| Category | Examples | Recovery Action |
|----------|----------|-----------------|
| **PTY Creation** | Failed to openpty, fork failed | Exit with error message |
| **Terminal Setup** | Failed to set raw mode | Restore terminal, exit |
| **Validation** | Watchtower unreachable | **Fail closed** - deny command |
| **Validation** | Timeout | Deny command, show timeout error |
| **Bash Exit** | Normal termination | Forward exit code, exit sevsh |
| **Bash Exit** | Signal termination | Forward signal info, exit sevsh |
| **Window Resize** | SIGWINCH | Resize both PTYs |
| **I/O Error** | Read/write failure | Log error, attempt recovery |
| **Signal** | SIGINT (Ctrl+C) | Clear buffer, return to IDLE |

### Fail-Closed Principle

**Critical Security Rule:** If validation cannot be performed, deny the command.

```rust
impl WatchtowerValidator {
    async fn validate(&self, command: &str) -> Result<Verdict, ValidationError> {
        match self.client.post(&self.url).json(&request).send().await {
            Ok(response) => {
                // Parse and return verdict
            }
            Err(e) => {
                // FAIL CLOSED: Return denial
                Ok(Verdict {
                    allowed: false,
                    status: "UNREACHABLE".to_string(),
                    reason: format!("Watchtower unreachable: {}", e),
                    confidence: 1.0,
                })
            }
        }
    }
}
```

### Error Display to User

| Error | Display Format |
|-------|---------------|
| Command denied | `SEVORIX BLOCKED: <reason>` |
| Validation timeout | `SEVORIX TIMEOUT: Command validation timed out` |
| Watchtower unreachable | `SEVORIX ERROR: Cannot reach Watchtower - <error>` |
| Internal error | `SEVORIX INTERNAL ERROR: <description>` |

### Signal Handling

```rust
fn setup_signal_handlers(multiplexer: &mut PtyMultiplexer) {
    // SIGWINCH - Window size change
    ctrlc::set_handler(move || {
        // Resize PTYs
    });

    // SIGINT - Ctrl+C (handled in input processing, not as signal)
    // SIGQUIT - Ctrl+\ (passed to bash in passthrough mode, ignored in validation mode)
    // SIGTERM - Graceful shutdown
}
```

### Cleanup on Exit

```rust
impl Drop for PtyMultiplexer {
    fn drop(&mut self) {
        // 1. Restore terminal settings
        let _ = self.input_pty.restore_terminal();

        // 2. Kill bash process if still running
        if self.output_pty.is_running() {
            let _ = signal::kill(self.output_pty.child_pid, Signal::SIGTERM);
            // Wait briefly, then SIGKILL if still running
            std::thread::sleep(Duration::from_millis(100));
            if self.output_pty.is_running() {
                let _ = signal::kill(self.output_pty.child_pid, Signal::SIGKILL);
            }
        }

        // 3. Close PTY file descriptors (handled by Drop implementations)
    }
}
```

## Event Loop Pseudocode

```rust
impl PtyMultiplexer {
    pub fn run(&mut self) -> Result<ExitStatus, PtyError> {
        let mut poll_fds = [
            PollFd::new(self.input_pty.fd(), PollFlags::POLLIN),
            PollFd::new(self.output_pty.fd(), PollFlags::POLLIN),
        ];

        loop {
            // Poll for events
            let n_ready = poll(&mut poll_fds, -1)?;

            // Handle input from user
            if poll_fds[0].revents().contains(PollFlags::POLLIN) {
                let mut buf = [0u8; 1];
                self.input_pty.read(&mut buf)?;

                match self.mode {
                    MultiplexerMode::Validation => {
                        self.handle_input_char(buf[0])?;
                    }
                    MultiplexerMode::Passthrough => {
                        // Forward directly to bash
                        self.output_pty.write(&buf)?;
                    }
                }
            }

            // Handle output from bash
            if poll_fds[1].revents().contains(PollFlags::POLLIN) {
                let mut buf = [0u8; 4096];
                let n = self.output_pty.read(&mut buf)?;
                self.input_pty.write(&buf[..n])?;  // Echo to user

                // Check if bash exited
                if !self.output_pty.is_running() {
                    return self.output_pty.wait();
                }
            }

            // Handle window resize (SIGWINCH)
            if self.window_size_changed() {
                let (rows, cols) = self.get_terminal_size()?;
                self.input_pty.resize(rows, cols)?;
                self.output_pty.resize(rows, cols)?;
            }
        }
    }
}
```

## Integration with Existing Components

### Watchtower Integration

The multiplexer uses the existing `/analyze` endpoint:

```rust
let request = json!({
    "payload": command,
    "agent": "sevsh-pty",
    "context": "Shell"
});
```

### eBPF Daemon Integration

The multiplexer runs alongside the eBPF daemon:
- eBPF provides syscall-level observability
- Multiplexer provides shell-level validation
- Both layers operate independently (four-layer architecture)

### Sandbox Integration

Existing sandbox mode (network namespace isolation) applies:
- Multiplexer runs inside the sandbox
- Unix socket bridges proxy traffic to host
- Port forwarding works as before

## File Structure

```
src/
├── bin/
│   └── sevsh.rs              # Entry point, mode selection
├── pty/
│   ├── mod.rs                # PTY module exports
│   ├── multiplexer.rs        # PtyMultiplexer implementation
│   ├── input_pty.rs          # InputPty implementation
│   ├── output_pty.rs         # OutputPty implementation
│   ├── buffer.rs             # CommandBuffer implementation
│   ├── passthrough.rs        # PassthroughDetector
│   └── validator.rs          # WatchtowerValidator
└── ...
```

## Performance Considerations

1. **Low-latency echo:** Characters echo immediately, no buffering
2. **Async validation:** Non-blocking, with timeout
3. **Minimal copies:** Use `io::copy_bidirectional` for passthrough mode
4. **Efficient polling:** Single poll() for both PTYs

## Testing Strategy

1. **Unit tests:** CommandBuffer, PassthroughDetector, validation logic
2. **Integration tests:** PTY pair creation, bash spawning
3. **Manual tests:** vim, less, top (passthrough); denied commands (validation)
4. **Stress tests:** Rapid typing, long lines, special characters

## Security Considerations

1. **No bypass via completion:** Tab completion forwards to bash, not command text
2. **No bypass via passthrough:** Passthrough only for known interactive commands
3. **Fail closed:** Unreachable Watchtower = deny command
4. **Signal safety:** Ctrl+C clears buffer, doesn't bypass validation
5. **No command injection:** Line is validated as a whole before forwarding
