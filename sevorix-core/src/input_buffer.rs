// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

//! Input buffering for PTY multiplexer.
//!
//! This module provides character-by-character input buffering with immediate echo,
//! designed for PTY multiplexer-based shell command interception.
//!
//! # Architecture
//!
//! ```text
//! User → sevsh PTY (multiplexer)
//!          ↓
//!       User types, sevsh echoes immediately (preserves interactivity)
//!          ↓
//!       On Enter: sevsh validates complete command
//!          ↓
//!       ALLOW → forward line to bash PTY
//!       DENY  → show error, don't forward to bash
//! ```
//!
//! # Special Characters
//!
//! - Backspace/Delete: Remove last character from buffer, echo delete sequence
//! - Ctrl+C: Clear buffer, send SIGINT to bash
//! - Ctrl+D: EOF handling (close input if buffer empty)
//! - Tab: Forward to bash for completion (passthrough mode)
//! - Arrow keys: Forward to bash for history (passthrough mode)

use std::io::{self, Write};

/// Result type for input buffer operations.
pub type Result<T> = std::result::Result<T, InputBufferError>;

/// Errors that can occur during input buffer operations.
#[derive(Debug)]
pub enum InputBufferError {
    /// IO error during echo operation
    Io(io::Error),
    /// Invalid UTF-8 sequence in input
    InvalidUtf8,
    /// Buffer overflow
    BufferOverflow { max_size: usize },
}

impl std::fmt::Display for InputBufferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InputBufferError::Io(e) => write!(f, "IO error: {}", e),
            InputBufferError::InvalidUtf8 => write!(f, "Invalid UTF-8 sequence"),
            InputBufferError::BufferOverflow { max_size } => {
                write!(f, "Buffer overflow (max {} bytes)", max_size)
            }
        }
    }
}

impl std::error::Error for InputBufferError {}

impl From<io::Error> for InputBufferError {
    fn from(e: io::Error) -> Self {
        InputBufferError::Io(e)
    }
}

/// Action to take after processing a character.
#[derive(Debug, Clone, PartialEq)]
pub enum InputAction {
    /// Echo the character to the terminal
    Echo,
    /// Line is complete, validate it
    ValidateLine(String),
    /// Forward raw bytes to bash (passthrough mode for tab, arrows)
    ForwardToBash(Vec<u8>),
    /// Send SIGINT to bash (Ctrl+C)
    SendSigint,
    /// Send EOF to bash (Ctrl+D with empty buffer)
    SendEof,
    /// No action needed (e.g., backspace on empty buffer)
    NoAction,
    /// Enter passthrough mode for interactive programs
    EnterPassthrough,
    /// Exit passthrough mode
    ExitPassthrough,
}

/// State machine for input buffering.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InputMode {
    /// Normal mode: buffer input, validate on Enter
    Normal,
    /// Passthrough mode: forward all input directly to bash
    Passthrough,
    /// Escape sequence mode: collecting ANSI escape sequence bytes
    EscapeSequence,
}

/// Input buffer for character-by-character processing.
///
/// This struct maintains the current line buffer and handles special character
/// processing for PTY multiplexer input.
pub struct InputBuffer {
    /// Current line being buffered
    line: String,
    /// Current input mode
    mode: InputMode,
    /// Maximum buffer size (to prevent memory exhaustion)
    max_size: usize,
    /// Escape sequence accumulator
    escape_buffer: Vec<u8>,
    /// Whether we're in raw terminal mode
    in_raw_mode: bool,
}

impl Default for InputBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl InputBuffer {
    /// Create a new input buffer with default settings.
    pub fn new() -> Self {
        Self {
            line: String::new(),
            mode: InputMode::Normal,
            max_size: 4096, // Reasonable command line limit
            escape_buffer: Vec::new(),
            in_raw_mode: true,
        }
    }

    /// Create a new input buffer with a custom maximum size.
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            line: String::new(),
            mode: InputMode::Normal,
            max_size,
            escape_buffer: Vec::new(),
            in_raw_mode: true,
        }
    }

    /// Get the current line content.
    pub fn line(&self) -> &str {
        &self.line
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.line.is_empty()
    }

    /// Get the current input mode.
    pub fn mode(&self) -> InputMode {
        self.mode
    }

    /// Set whether we're in raw terminal mode.
    pub fn set_raw_mode(&mut self, raw: bool) {
        self.in_raw_mode = raw;
    }

    /// Clear the current line buffer.
    pub fn clear(&mut self) {
        self.line.clear();
        self.escape_buffer.clear();
    }

    /// Process a single character and return the action to take.
    ///
    /// This method handles:
    /// - Regular characters: add to buffer, echo
    /// - Enter: validate line
    /// - Backspace/Delete: remove from buffer, echo delete
    /// - Ctrl+C: send SIGINT
    /// - Ctrl+D: EOF handling
    /// - Tab: forward to bash
    /// - Arrow keys: forward to bash
    pub fn handle_char<W: Write>(&mut self, c: char, output: &mut W) -> Result<InputAction> {
        match self.mode {
            InputMode::Normal => self.handle_normal_char(c, output),
            InputMode::EscapeSequence => self.handle_escape_char(c, output),
            InputMode::Passthrough => self.handle_passthrough_char(c, output),
        }
    }

    /// Process a character in normal mode.
    fn handle_normal_char<W: Write>(&mut self, c: char, output: &mut W) -> Result<InputAction> {
        match c {
            // Enter/Return: validate line
            '\n' | '\r' => {
                let line = self.line.clone();
                self.line.clear(); // Clear buffer after enter
                output.write_all(b"\r\n")?;
                output.flush()?;
                Ok(InputAction::ValidateLine(line))
            }

            // Backspace (DEL character)
            '\x7f' => {
                if self.line.pop().is_some() {
                    // Echo backspace sequence: backspace, space, backspace
                    // This clears the character from the terminal
                    output.write_all(b"\x08 \x08")?;
                    output.flush()?;
                }
                Ok(InputAction::NoAction)
            }

            // Ctrl+H (also backspace in some terminals)
            '\x08' => {
                if self.line.pop().is_some() {
                    output.write_all(b"\x08 \x08")?;
                    output.flush()?;
                }
                Ok(InputAction::NoAction)
            }

            // Ctrl+C: interrupt
            '\x03' => {
                output.write_all(b"^C\r\n")?;
                output.flush()?;
                self.clear();
                Ok(InputAction::SendSigint)
            }

            // Ctrl+D: EOF
            '\x04' => {
                if self.line.is_empty() {
                    output.write_all(b"^D\r\n")?;
                    output.flush()?;
                    Ok(InputAction::SendEof)
                } else {
                    // Ctrl+D with content: do nothing (some shells delete forward)
                    Ok(InputAction::NoAction)
                }
            }

            // Ctrl+U: clear line
            '\x15' => {
                if !self.line.is_empty() {
                    // Move cursor to start, clear line
                    output.write_all(b"\x1b[2K\r")?;
                    output.flush()?;
                    self.line.clear();
                }
                Ok(InputAction::NoAction)
            }

            // Tab: forward to bash for completion
            '\t' => {
                output.write_all(b"\t")?;
                output.flush()?;
                Ok(InputAction::ForwardToBash(vec![b'\t']))
            }

            // ESC: start escape sequence
            '\x1b' => {
                self.escape_buffer.clear();
                self.escape_buffer.push(0x1b);
                self.mode = InputMode::EscapeSequence;
                Ok(InputAction::NoAction)
            }

            // Regular character
            c => {
                // Check buffer size limit
                if self.line.len() >= self.max_size {
                    return Err(InputBufferError::BufferOverflow {
                        max_size: self.max_size,
                    });
                }

                // Add to buffer
                self.line.push(c);

                // Echo character
                output.write_all(c.to_string().as_bytes())?;
                output.flush()?;

                Ok(InputAction::Echo)
            }
        }
    }

    /// Process a character while in escape sequence mode.
    fn handle_escape_char<W: Write>(&mut self, c: char, output: &mut W) -> Result<InputAction> {
        // Accumulate escape sequence
        self.escape_buffer.push(c as u8);

        // Check for common terminal sequences
        let escape_len = self.escape_buffer.len();

        // ANSI escape sequences are typically ESC [ <params> <final byte>
        // Final bytes are in range 0x40-0x7E (@A-Z[\]^_`a-z{|}~)
        // Or they can be single character sequences like ESC ESC

        if escape_len == 2 && c == '[' {
            // Start of CSI sequence, continue collecting
            Ok(InputAction::NoAction)
        } else if escape_len == 2 && (c == 'O' || c == 'N') {
            // Start of SS3 sequence (function keys)
            Ok(InputAction::NoAction)
        } else if escape_len >= 2 && c == 'O' {
            // Function key sequences like F1-F4: ESC O P/Q/R/S
            // These are 3 bytes total
            self.mode = InputMode::Normal;
            let seq = self.escape_buffer.clone();
            output.write_all(&seq)?;
            output.flush()?;
            Ok(InputAction::ForwardToBash(seq))
        } else if escape_len >= 2 && (c == '[' || c.is_ascii_digit() || c == ';') {
            // CSI sequence continuing (e.g., ESC [ 5 ~ for Page Up)
            Ok(InputAction::NoAction)
        } else if escape_len >= 3 && (c as u8) >= 0x40 && (c as u8) <= 0x7E {
            // End of CSI sequence
            self.mode = InputMode::Normal;
            let seq = self.escape_buffer.clone();

            // Check for arrow keys and home/end
            match &self.escape_buffer[..] {
                // Arrow keys: ESC [ A/B/C/D
                [0x1b, b'[', b'A']
                | [0x1b, b'[', b'B']
                | [0x1b, b'[', b'C']
                | [0x1b, b'[', b'D'] => {
                    output.write_all(&seq)?;
                    output.flush()?;
                    Ok(InputAction::ForwardToBash(seq))
                }
                // Home/End: ESC [ H or ESC [ F
                [0x1b, b'[', b'H'] | [0x1b, b'[', b'F'] => {
                    output.write_all(&seq)?;
                    output.flush()?;
                    Ok(InputAction::ForwardToBash(seq))
                }
                // Other sequences (Page Up/Down, etc.)
                _ => {
                    output.write_all(&seq)?;
                    output.flush()?;
                    Ok(InputAction::ForwardToBash(seq))
                }
            }
        } else if escape_len == 2 && c == '\x1b' {
            // Double ESC: cancel escape sequence
            self.mode = InputMode::Normal;
            Ok(InputAction::NoAction)
        } else if escape_len > 8 {
            // Sequence too long, abort
            self.mode = InputMode::Normal;
            self.escape_buffer.clear();
            Ok(InputAction::NoAction)
        } else {
            // Unknown sequence character, continue collecting
            Ok(InputAction::NoAction)
        }
    }

    /// Process a character in passthrough mode.
    fn handle_passthrough_char<W: Write>(
        &mut self,
        c: char,
        output: &mut W,
    ) -> Result<InputAction> {
        // In passthrough mode, forward everything directly to bash
        let mut buf = [0u8; 4];
        let bytes = c.encode_utf8(&mut buf);
        output.write_all(bytes.as_bytes())?;
        output.flush()?;
        Ok(InputAction::ForwardToBash(bytes.as_bytes().to_vec()))
    }

    /// Enter passthrough mode.
    pub fn enter_passthrough(&mut self) {
        self.mode = InputMode::Passthrough;
    }

    /// Exit passthrough mode and return to normal buffering.
    pub fn exit_passthrough(&mut self) {
        self.mode = InputMode::Normal;
    }

    /// Handle a raw byte from the terminal.
    ///
    /// This is useful for handling non-UTF8 sequences or raw control codes.
    /// Returns the action and whether the byte was consumed.
    pub fn handle_byte<W: Write>(&mut self, byte: u8, output: &mut W) -> Result<InputAction> {
        // Try to decode as UTF-8 character
        if byte.is_ascii() {
            self.handle_char(byte as char, output)
        } else {
            // Non-ASCII byte - we need to accumulate UTF-8 bytes
            // For simplicity, we'll accumulate and decode when complete
            // This is a simplified implementation - full UTF-8 handling would need
            // proper state machine for multi-byte sequences
            if byte & 0xC0 == 0xC0 {
                // Start of UTF-8 sequence
                self.escape_buffer.clear();
                self.escape_buffer.push(byte);
                Ok(InputAction::NoAction)
            } else if !self.escape_buffer.is_empty() {
                self.escape_buffer.push(byte);
                if let Ok(s) = std::str::from_utf8(&self.escape_buffer) {
                    if let Some(c) = s.chars().next() {
                        self.escape_buffer.clear();
                        return self.handle_char(c, output);
                    }
                }
                // If not complete yet, continue
                Ok(InputAction::NoAction)
            } else {
                // Orphan continuation byte - ignore or forward
                Ok(InputAction::ForwardToBash(vec![byte]))
            }
        }
    }
}

/// Echo helper functions for terminal control.
pub mod echo {
    use std::io::{self, Write};

    /// Write a character to the terminal with proper echo.
    pub fn echo_char<W: Write>(output: &mut W, c: char) -> io::Result<()> {
        output.write_all(c.to_string().as_bytes())?;
        output.flush()
    }

    /// Write a backspace sequence (move back, clear, move back).
    pub fn echo_backspace<W: Write>(output: &mut W) -> io::Result<()> {
        output.write_all(b"\x08 \x08")?;
        output.flush()
    }

    /// Write a newline sequence.
    pub fn echo_newline<W: Write>(output: &mut W) -> io::Result<()> {
        output.write_all(b"\r\n")?;
        output.flush()
    }

    /// Clear the current line.
    pub fn clear_line<W: Write>(output: &mut W) -> io::Result<()> {
        output.write_all(b"\x1b[2K\r")?;
        output.flush()
    }

    /// Write interrupt indicator (^C).
    pub fn echo_interrupt<W: Write>(output: &mut W) -> io::Result<()> {
        output.write_all(b"^C\r\n")?;
        output.flush()
    }

    /// Write EOF indicator (^D).
    pub fn echo_eof<W: Write>(output: &mut W) -> io::Result<()> {
        output.write_all(b"^D\r\n")?;
        output.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_buffer() -> InputBuffer {
        InputBuffer::new()
    }

    #[test]
    fn test_basic_character_echo() {
        let mut buf = make_buffer();
        let mut output = Cursor::new(Vec::new());

        let action = buf.handle_char('a', &mut output).unwrap();
        assert_eq!(action, InputAction::Echo);
        assert_eq!(buf.line(), "a");
        assert_eq!(output.into_inner(), b"a");
    }

    #[test]
    fn test_multiple_characters() {
        let mut buf = make_buffer();
        let mut output = Cursor::new(Vec::new());

        for c in "hello".chars() {
            buf.handle_char(c, &mut output).unwrap();
        }
        assert_eq!(buf.line(), "hello");
    }

    #[test]
    fn test_enter_key() {
        let mut buf = make_buffer();
        let mut output = Cursor::new(Vec::new());

        for c in "test".chars() {
            buf.handle_char(c, &mut output).unwrap();
        }
        output.set_position(0);

        let action = buf.handle_char('\n', &mut output).unwrap();
        assert_eq!(action, InputAction::ValidateLine("test".to_string()));
        assert!(buf.is_empty()); // Buffer cleared after enter
    }

    #[test]
    fn test_backspace() {
        let mut buf = make_buffer();
        let mut output = Cursor::new(Vec::new());

        for c in "hello".chars() {
            buf.handle_char(c, &mut output).unwrap();
        }
        assert_eq!(buf.line(), "hello");

        output.set_position(0);
        let action = buf.handle_char('\x7f', &mut output).unwrap();
        assert_eq!(action, InputAction::NoAction);
        assert_eq!(buf.line(), "hell");
    }

    #[test]
    fn test_backspace_empty() {
        let mut buf = make_buffer();
        let mut output = Cursor::new(Vec::new());

        let action = buf.handle_char('\x7f', &mut output).unwrap();
        assert_eq!(action, InputAction::NoAction);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_ctrl_c() {
        let mut buf = make_buffer();
        let mut output = Cursor::new(Vec::new());

        for c in "some command".chars() {
            buf.handle_char(c, &mut output).unwrap();
        }
        assert_eq!(buf.line(), "some command");

        output.set_position(0);
        let action = buf.handle_char('\x03', &mut output).unwrap();
        assert_eq!(action, InputAction::SendSigint);
        assert!(buf.is_empty()); // Buffer cleared
    }

    #[test]
    fn test_ctrl_d_empty_buffer() {
        let mut buf = make_buffer();
        let mut output = Cursor::new(Vec::new());

        let action = buf.handle_char('\x04', &mut output).unwrap();
        assert_eq!(action, InputAction::SendEof);
    }

    #[test]
    fn test_ctrl_d_with_content() {
        let mut buf = make_buffer();
        let mut output = Cursor::new(Vec::new());

        for c in "test".chars() {
            buf.handle_char(c, &mut output).unwrap();
        }

        output.set_position(0);
        let action = buf.handle_char('\x04', &mut output).unwrap();
        assert_eq!(action, InputAction::NoAction);
        assert_eq!(buf.line(), "test"); // Buffer not cleared
    }

    #[test]
    fn test_ctrl_u_clear_line() {
        let mut buf = make_buffer();
        let mut output = Cursor::new(Vec::new());

        for c in "some long command".chars() {
            buf.handle_char(c, &mut output).unwrap();
        }
        assert!(!buf.is_empty());

        output.set_position(0);
        let action = buf.handle_char('\x15', &mut output).unwrap();
        assert_eq!(action, InputAction::NoAction);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_tab_forwarding() {
        let mut buf = make_buffer();
        let mut output = Cursor::new(Vec::new());

        let action = buf.handle_char('\t', &mut output).unwrap();
        assert_eq!(action, InputAction::ForwardToBash(vec![b'\t']));
    }

    #[test]
    fn test_arrow_keys() {
        let mut buf = make_buffer();
        let mut output = Cursor::new(Vec::new());

        // Send ESC [ A (up arrow)
        let action = buf.handle_char('\x1b', &mut output).unwrap();
        assert_eq!(action, InputAction::NoAction);

        let action = buf.handle_char('[', &mut output).unwrap();
        assert_eq!(action, InputAction::NoAction);

        let action = buf.handle_char('A', &mut output).unwrap();
        assert_eq!(action, InputAction::ForwardToBash(vec![0x1b, b'[', b'A']));
        assert_eq!(buf.mode(), InputMode::Normal);
    }

    #[test]
    fn test_buffer_size_limit() {
        let mut buf = InputBuffer::with_max_size(5);
        let mut output = Cursor::new(Vec::new());

        // Fill buffer
        for c in "hello".chars() {
            buf.handle_char(c, &mut output).unwrap();
        }
        assert_eq!(buf.line(), "hello");

        // Try to add more - should fail
        let result = buf.handle_char('!', &mut output);
        assert!(matches!(
            result,
            Err(InputBufferError::BufferOverflow { .. })
        ));
    }

    #[test]
    fn test_passthrough_mode() {
        let mut buf = InputBuffer::new();
        buf.enter_passthrough();

        let mut output = Cursor::new(Vec::new());

        // In passthrough, all characters forwarded to bash
        let action = buf.handle_char('x', &mut output).unwrap();
        assert_eq!(action, InputAction::ForwardToBash(vec![b'x']));
    }

    #[test]
    fn test_passthrough_exit() {
        let mut buf = InputBuffer::new();
        buf.enter_passthrough();
        assert_eq!(buf.mode(), InputMode::Passthrough);

        buf.exit_passthrough();
        assert_eq!(buf.mode(), InputMode::Normal);
    }

    #[test]
    fn test_escape_sequence_mode() {
        let mut buf = make_buffer();
        let mut output = Cursor::new(Vec::new());

        // ESC enters escape sequence mode
        let action = buf.handle_char('\x1b', &mut output).unwrap();
        assert_eq!(action, InputAction::NoAction);
        assert_eq!(buf.mode(), InputMode::EscapeSequence);
    }

    #[test]
    fn test_carriage_return() {
        let mut buf = make_buffer();
        let mut output = Cursor::new(Vec::new());

        for c in "test".chars() {
            buf.handle_char(c, &mut output).unwrap();
        }

        output.set_position(0);
        let action = buf.handle_char('\r', &mut output).unwrap();
        assert_eq!(action, InputAction::ValidateLine("test".to_string()));
    }

    #[test]
    fn test_clear() {
        let mut buf = make_buffer();
        let mut output = Cursor::new(Vec::new());

        for c in "test command".chars() {
            buf.handle_char(c, &mut output).unwrap();
        }
        assert!(!buf.is_empty());

        buf.clear();
        assert!(buf.is_empty());
    }

    #[test]
    fn test_raw_mode_setting() {
        let mut buf = InputBuffer::new();
        assert!(buf.in_raw_mode);

        buf.set_raw_mode(false);
        assert!(!buf.in_raw_mode);
    }

    #[test]
    fn test_echo_helper() {
        let mut output = Cursor::new(Vec::new());

        echo::echo_char(&mut output, 'x').unwrap();
        assert_eq!(output.into_inner(), b"x");
    }

    #[test]
    fn test_echo_backspace_helper() {
        let mut output = Cursor::new(Vec::new());

        echo::echo_backspace(&mut output).unwrap();
        assert_eq!(output.into_inner(), b"\x08 \x08");
    }

    #[test]
    fn test_echo_newline_helper() {
        let mut output = Cursor::new(Vec::new());

        echo::echo_newline(&mut output).unwrap();
        assert_eq!(output.into_inner(), b"\r\n");
    }

    #[test]
    fn test_echo_interrupt_helper() {
        let mut output = Cursor::new(Vec::new());

        echo::echo_interrupt(&mut output).unwrap();
        assert_eq!(output.into_inner(), b"^C\r\n");
    }

    #[test]
    fn test_echo_eof_helper() {
        let mut output = Cursor::new(Vec::new());

        echo::echo_eof(&mut output).unwrap();
        assert_eq!(output.into_inner(), b"^D\r\n");
    }

    #[test]
    fn test_clear_line_helper() {
        let mut output = Cursor::new(Vec::new());

        echo::clear_line(&mut output).unwrap();
        assert_eq!(output.into_inner(), b"\x1b[2K\r");
    }
}
