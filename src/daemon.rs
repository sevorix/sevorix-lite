// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

use anyhow::{Context, Result};
use daemonize::{Daemonize, Outcome};
use directories::{ProjectDirs, UserDirs};
use libc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Poll a PID file until a valid PID is found or retries are exhausted.
fn poll_pid_file(path: &PathBuf, retries: u32, delay_ms: u64) -> Option<i32> {
    for _ in 0..retries {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(pid) = content.trim().parse::<i32>() {
                return Some(pid);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
    }
    // one final try
    fs::read_to_string(path).ok()?.trim().parse::<i32>().ok()
}

/// Return the project state directory, creating it if needed.
fn state_dir() -> Result<PathBuf> {
    let proj_dirs = ProjectDirs::from("com", "sevorix", "sevorix")
        .ok_or_else(|| anyhow::anyhow!("Could not determine project directories"))?;
    let dir = proj_dirs
        .state_dir()
        .unwrap_or_else(|| proj_dirs.cache_dir())
        .to_path_buf();
    fs::create_dir_all(&dir).context("Failed to create state directory")?;
    Ok(dir)
}

/// Return the sessions sub-directory inside the state directory.
fn sessions_dir() -> Result<PathBuf> {
    let dir = state_dir()?.join("sessions");
    fs::create_dir_all(&dir).context("Failed to create sessions directory")?;
    Ok(dir)
}

/// Attempt to find an available TCP port starting from `start`, trying up to 100 candidates.
pub fn find_available_port(start: u16) -> u16 {
    for p in start..=start.saturating_add(99) {
        if std::net::TcpListener::bind(("127.0.0.1", p)).is_ok() {
            return p;
        }
    }
    start
}

/// Metadata stored alongside a running session's PID file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub name: String,
    pub session_id: String,
    pub port: u16,
    pub role: Option<String>,
    pub pid: i32,
}

/// Manages Watchtower daemon lifecycle (start/stop/status) for a named session.
pub struct DaemonManager {
    pub session_name: String,
    pid_path: PathBuf,
    meta_path: PathBuf,
    log_path: PathBuf,
}

/// Manages eBPF daemon lifecycle (start/stop/status).
pub struct EbpfDaemonManager {
    pid_path: PathBuf,
    log_path: PathBuf,
}

impl DaemonManager {
    /// Create a manager for a named session (creates the sessions/ directory if needed).
    pub fn new(session_name: &str) -> Result<Self> {
        let sdir = sessions_dir()?;
        let state = state_dir()?;
        Ok(Self {
            session_name: session_name.to_string(),
            pid_path: sdir.join(format!("{}.pid", session_name)),
            meta_path: sdir.join(format!("{}.json", session_name)),
            log_path: state.join("sevorix.log"),
        })
    }

    /// List all sessions in the sessions directory, checking if each PID is alive.
    pub fn list_sessions() -> Result<Vec<(SessionInfo, bool)>> {
        let sdir = match sessions_dir() {
            Ok(d) => d,
            Err(_) => return Ok(vec![]),
        };
        let mut sessions = Vec::new();
        if let Ok(entries) = fs::read_dir(&sdir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("json") {
                    continue;
                }
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(info) = serde_json::from_str::<SessionInfo>(&content) {
                        let running = unsafe { libc::kill(info.pid, 0) } == 0;
                        if !running {
                            // Clean up stale files
                            let _ = fs::remove_file(&path);
                            let pid_path = path.with_extension("pid");
                            let _ = fs::remove_file(&pid_path);
                        } else {
                            sessions.push((info, running));
                        }
                    }
                }
            }
        }

        // Include any legacy single-session daemon (pre-multi-session sevorix.pid).
        // These won't have a sessions/<name>.json entry but are still occupying a port.
        if let Ok(state) = state_dir() {
            let legacy_pid_path = state.join("sevorix.pid");
            if let Ok(content) = fs::read_to_string(&legacy_pid_path) {
                if let Ok(pid) = content.trim().parse::<i32>() {
                    let running = pid > 0 && unsafe { libc::kill(pid, 0) } == 0;
                    if running {
                        // Surface as a synthetic "(legacy)" session so the user can see
                        // and stop it. Port is unknown without inspecting /proc/net/tcp.
                        let info = SessionInfo {
                            name: "(legacy)".to_string(),
                            session_id: String::new(),
                            port: 0,
                            role: None,
                            pid,
                        };
                        sessions.push((info, true));
                    } else {
                        let _ = fs::remove_file(&legacy_pid_path);
                    }
                }
            }
        }

        sessions.sort_by(|a, b| a.0.name.cmp(&b.0.name));
        Ok(sessions)
    }

    /// Stop all running sessions.
    pub fn stop_all() -> Result<()> {
        let sessions = Self::list_sessions()?;
        if sessions.is_empty() {
            println!("No running sessions.");
            return Ok(());
        }
        for (info, _) in sessions {
            if info.name == "(legacy)" {
                // Legacy daemon: no sessions/<name>.pid — stop via direct kill.
                unsafe { libc::kill(info.pid, libc::SIGTERM) };
                if let Ok(state) = state_dir() {
                    let _ = fs::remove_file(state.join("sevorix.pid"));
                }
                println!("Legacy session stopped (PID: {})", info.pid);
            } else {
                let manager = Self::new(&info.name)?;
                manager.stop()?;
            }
        }
        Ok(())
    }

    pub fn start(
        &self,
        session_id: uuid::Uuid,
        port: u16,
        initial_role: Option<String>,
        start_ebpf: bool,
    ) -> Result<()> {
        if self.is_running() {
            println!(
                "Session '{}' is already running (PID: {})",
                self.session_name,
                self.read_pid().unwrap_or(0)
            );
            return Err(anyhow::anyhow!(
                "Session '{}' is already running.",
                self.session_name
            ));
        }

        // Pre-flight: verify the port is available before forking. Without this,
        // the bind error only surfaces inside the daemon child after the parent has
        // already printed "Sevorix Watchtower started." and exited, making it look
        // like startup succeeded when it actually failed.
        if let Err(e) = std::net::TcpListener::bind(("0.0.0.0", port)) {
            return Err(anyhow::anyhow!(
                "Port {} is already in use: {}. Stop the process occupying it first.",
                port,
                e
            ));
        }

        // Compute session log and traffic log paths
        let log_dir = if let Some(user_dirs) = UserDirs::new() {
            user_dirs.home_dir().join(".sevorix").join("logs")
        } else {
            PathBuf::from(".sevorix/logs")
        };
        let session_log_path = log_dir.join(format!("{}.log", session_id));
        let traffic_log_path = log_dir.join(format!("{}-traffic.jsonl", session_id));

        let stdout = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .context("Failed to open log file")?;
        let stderr = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .context("Failed to open log file")?;

        let daemonize = Daemonize::new()
            .pid_file(&self.pid_path)
            .chown_pid_file(true)
            .working_directory(std::env::current_dir().unwrap_or(PathBuf::from("/")))
            .stdout(stdout)
            .stderr(stderr);

        match daemonize.execute() {
            Outcome::Parent(Ok(_)) => {
                // Poll for watchtower PID (up to 2s)
                let wt_pid = self.poll_pid(20, 100);
                let wt_pid_val = wt_pid.unwrap_or(0);
                let wt_pid_str = wt_pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| format!("(see {})", self.pid_path.display()));

                // Write session metadata. If no role was passed via --role, fall back to
                // settings.json sevsh.default_role so that sevorix status reflects the
                // actual role the daemon will apply.
                let meta_role = initial_role.clone().or_else(|| {
                    crate::settings::Settings::load()
                        .sevsh
                        .and_then(|s| s.default_role)
                });
                let meta = SessionInfo {
                    name: self.session_name.clone(),
                    session_id: session_id.to_string(),
                    port,
                    role: meta_role,
                    pid: wt_pid_val,
                };
                if let Ok(json) = serde_json::to_string_pretty(&meta) {
                    let _ = fs::write(&self.meta_path, json);
                }

                let ebpf_pid_str = if start_ebpf {
                    let ebpf_pid_path = ProjectDirs::from("com", "sevorix", "sevorix")
                        .map(|d| {
                            d.state_dir()
                                .unwrap_or_else(|| d.cache_dir())
                                .join("sevorix-ebpf.pid")
                        })
                        .unwrap_or_else(|| PathBuf::from("sevorix-ebpf.pid"));
                    // Poll for eBPF PID (up to 4.5s — eBPF takes longer due to sudo)
                    let ebpf_pid = poll_pid_file(&ebpf_pid_path, 30, 150);
                    Some(
                        ebpf_pid
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| format!("(see {})", ebpf_pid_path.display())),
                    )
                } else {
                    None
                };

                println!("Sevorix Watchtower started.");
                println!("  Session name:    {}", self.session_name);
                println!("  Watchtower PID:  {}", wt_pid_str);
                if let Some(ref s) = ebpf_pid_str {
                    println!("  eBPF daemon PID: {}", s);
                }
                println!("  Session ID:      {}", session_id);
                if let Some(ref r) = initial_role {
                    println!("  Role:            {}", r);
                }
                println!("  Service log:     {}", self.log_path.display());
                println!("  Session log:     {}", session_log_path.display());
                println!("  Traffic log:     {}", traffic_log_path.display());
                println!("📡 API:            http://localhost:{}/analyze", port);
                println!(
                    "📊 Dashboard:      http://localhost:{}/dashboard/desktop.html",
                    port
                );

                std::process::exit(0);
            }
            Outcome::Parent(Err(e)) => Err(anyhow::anyhow!("Error daemonizing: {}", e)),
            Outcome::Child(Ok(_)) => Ok(()),
            Outcome::Child(Err(e)) => Err(anyhow::anyhow!("Error in daemon child: {}", e)),
        }
    }

    fn poll_pid(&self, retries: u32, delay_ms: u64) -> Option<i32> {
        poll_pid_file(&self.pid_path, retries, delay_ms)
    }

    pub fn stop(&self) -> Result<()> {
        if let Some(pid) = self.read_pid() {
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            if self.pid_path.exists() {
                let _ = fs::remove_file(&self.pid_path);
            }
            if self.meta_path.exists() {
                let _ = fs::remove_file(&self.meta_path);
            }
            println!("Session '{}' stopped (PID: {})", self.session_name, pid);
        } else {
            println!("Session '{}' is not running.", self.session_name);
        }
        Ok(())
    }

    pub fn status(&self) {
        if let Some(pid) = self.read_pid() {
            let res = unsafe { libc::kill(pid, 0) };
            if res == 0 {
                let port = self.read_meta().map(|m| m.port).unwrap_or(3000);
                let role = self
                    .read_meta()
                    .and_then(|m| m.role)
                    .unwrap_or_else(|| "(none)".to_string());
                println!("Session '{}' is running (PID: {})", self.session_name, pid);
                println!("  Port:     {}", port);
                println!("  Role:     {}", role);
                println!("  PID file: {}", self.pid_path.display());
                println!("  Logs:     {}", self.log_path.display());
                println!("📡 API:    http://localhost:{}/analyze", port);
                println!(
                    "📊 Dashboard: http://localhost:{}/dashboard/desktop.html",
                    port
                );
            } else {
                println!(
                    "Session '{}' PID file exists but process is gone. Cleaning up.",
                    self.session_name
                );
                let _ = fs::remove_file(&self.pid_path);
                let _ = fs::remove_file(&self.meta_path);
            }
        } else {
            println!("Session '{}' is NOT running.", self.session_name);
        }
    }

    pub fn is_running(&self) -> bool {
        if let Some(pid) = self.read_pid() {
            let res = unsafe { libc::kill(pid, 0) };
            if res == 0 {
                return true;
            }
        }
        false
    }

    pub fn read_meta(&self) -> Option<SessionInfo> {
        let content = fs::read_to_string(&self.meta_path).ok()?;
        serde_json::from_str(&content).ok()
    }

    fn read_pid(&self) -> Option<i32> {
        if let Ok(content) = fs::read_to_string(&self.pid_path) {
            content.trim().parse::<i32>().ok()
        } else {
            None
        }
    }
}

impl EbpfDaemonManager {
    pub fn new() -> Result<Self> {
        let proj_dirs = ProjectDirs::from("com", "sevorix", "sevorix")
            .ok_or_else(|| anyhow::anyhow!("Could not determine project directories"))?;

        let state_dir = proj_dirs
            .state_dir()
            .unwrap_or_else(|| proj_dirs.cache_dir());
        fs::create_dir_all(state_dir).context("Failed to create state directory")?;

        Ok(Self {
            pid_path: state_dir.join("sevorix-ebpf.pid"),
            log_path: state_dir.join("sevorix-ebpf.log"),
        })
    }

    /// Check if the eBPF daemon is running.
    pub fn is_running(&self) -> bool {
        if let Some(pid) = self.read_pid() {
            let res = unsafe { libc::kill(pid, 0) };
            if res == 0 {
                return true;
            }
        }
        false
    }

    /// Stop the eBPF daemon.
    pub fn stop(&self) -> Result<()> {
        if let Some(pid) = self.read_pid() {
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            if self.pid_path.exists() {
                let _ = fs::remove_file(&self.pid_path);
            }
            println!("eBPF daemon stopped (PID: {})", pid);
        } else {
            println!("eBPF daemon is not running.");
        }
        Ok(())
    }

    /// Print the status of the eBPF daemon.
    pub fn status(&self) {
        if let Some(pid) = self.read_pid() {
            let res = unsafe { libc::kill(pid, 0) };
            if res == 0 {
                println!("eBPF daemon is running (PID: {})", pid);
                println!("PID file: {}", self.pid_path.display());
                println!("Logs: {}", self.log_path.display());
            } else {
                println!("eBPF daemon PID file exists but process is gone. Cleaning up.");
                let _ = fs::remove_file(&self.pid_path);
            }
        } else {
            println!("eBPF daemon is NOT running.");
        }
    }

    fn read_pid(&self) -> Option<i32> {
        if let Ok(content) = fs::read_to_string(&self.pid_path) {
            content.trim().parse::<i32>().ok()
        } else {
            None
        }
    }
}

/// Check if the eBPF daemon is running (convenience function).
pub fn is_ebpf_daemon_running() -> bool {
    EbpfDaemonManager::new()
        .map(|m| m.is_running())
        .unwrap_or(false)
}

/// Check if any Watchtower session is running (convenience function).
pub fn is_watchtower_running() -> bool {
    DaemonManager::list_sessions()
        .map(|s| !s.is_empty())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_manager_new_creates_directory() {
        let result = DaemonManager::new("test-session");
        assert!(result.is_ok());
        let manager = result.unwrap();
        assert!(manager
            .pid_path
            .to_string_lossy()
            .contains("test-session.pid"));
        assert!(manager
            .meta_path
            .to_string_lossy()
            .contains("test-session.json"));
    }

    #[test]
    fn test_daemon_manager_pid_path_structure() {
        let manager = DaemonManager::new("mysession").unwrap();
        assert!(manager.pid_path.ends_with("mysession.pid"));
    }

    #[test]
    fn test_daemon_manager_log_path_structure() {
        let manager = DaemonManager::new("mysession").unwrap();
        assert!(manager.log_path.ends_with("sevorix.log"));
    }

    #[test]
    fn test_is_running_no_pid_file() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = dir.path().join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        let manager = DaemonManager {
            session_name: "test".to_string(),
            pid_path: sessions.join("test.pid"),
            meta_path: sessions.join("test.json"),
            log_path: dir.path().join("sevorix.log"),
        };
        assert!(!manager.is_running());
    }

    #[test]
    fn test_read_pid_empty_content() {
        let content = "";
        let result: Option<i32> = content.trim().parse().ok();
        assert!(result.is_none());
    }

    #[test]
    fn test_read_pid_valid_pid() {
        let content = "12345";
        let result: Option<i32> = content.trim().parse().ok();
        assert_eq!(result, Some(12345));
    }

    #[test]
    fn test_read_pid_with_whitespace() {
        let content = "  12345  \n";
        let result: Option<i32> = content.trim().parse().ok();
        assert_eq!(result, Some(12345));
    }

    #[test]
    fn test_read_pid_invalid_content() {
        let content = "not a pid";
        let result: Option<i32> = content.trim().parse().ok();
        assert!(result.is_none());
    }

    #[test]
    fn test_status_not_running_no_pid() {
        let manager = DaemonManager::new("status-test").unwrap();
        manager.status();
    }

    #[test]
    fn test_stop_no_process() {
        let manager = DaemonManager::new("stop-test").unwrap();
        let result = manager.stop();
        assert!(result.is_ok());
    }

    #[test]
    fn test_pid_path_is_in_state_dir() {
        let manager = DaemonManager::new("path-test").unwrap();
        let path_str = manager.pid_path.to_string_lossy();
        assert!(path_str.contains("sevorix"));
    }

    #[test]
    fn test_log_path_is_in_state_dir() {
        let manager = DaemonManager::new("log-test").unwrap();
        let path_str = manager.log_path.to_string_lossy();
        assert!(path_str.contains("sevorix"));
    }

    #[test]
    fn test_list_sessions_empty() {
        // list_sessions should not panic even if sessions dir is empty or missing
        let result = DaemonManager::list_sessions();
        assert!(result.is_ok());
    }

    #[test]
    fn test_daemon_read_pid_returns_none_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = dir.path().join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        let manager = DaemonManager {
            session_name: "test".to_string(),
            pid_path: sessions.join("test.pid"),
            meta_path: sessions.join("test.json"),
            log_path: dir.path().join("sevorix.log"),
        };
        assert!(manager.read_pid().is_none());
    }

    #[test]
    fn test_daemon_read_pid_returns_value_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = dir.path().join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        let pid_path = sessions.join("test.pid");
        fs::write(&pid_path, "99999").unwrap();
        let manager = DaemonManager {
            session_name: "test".to_string(),
            pid_path,
            meta_path: sessions.join("test.json"),
            log_path: dir.path().join("sevorix.log"),
        };
        assert_eq!(manager.read_pid(), Some(99999));
    }

    #[test]
    fn test_daemon_stop_no_pid_file() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = dir.path().join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        let manager = DaemonManager {
            session_name: "test".to_string(),
            pid_path: sessions.join("test.pid"),
            meta_path: sessions.join("test.json"),
            log_path: dir.path().join("sevorix.log"),
        };
        let result = manager.stop();
        assert!(result.is_ok());
    }

    #[test]
    fn test_daemon_status_no_pid_file() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = dir.path().join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        let manager = DaemonManager {
            session_name: "test".to_string(),
            pid_path: sessions.join("test.pid"),
            meta_path: sessions.join("test.json"),
            log_path: dir.path().join("sevorix.log"),
        };
        manager.status();
    }

    #[test]
    fn test_ebpf_daemon_manager_new() {
        let result = EbpfDaemonManager::new();
        assert!(result.is_ok());
        let manager = result.unwrap();
        assert!(manager.pid_path.ends_with("sevorix-ebpf.pid"));
        assert!(manager.log_path.ends_with("sevorix-ebpf.log"));
    }

    #[test]
    fn test_ebpf_daemon_is_running_no_pid_file() {
        let dir = tempfile::tempdir().unwrap();
        let manager = EbpfDaemonManager {
            pid_path: dir.path().join("sevorix-ebpf.pid"),
            log_path: dir.path().join("sevorix-ebpf.log"),
        };
        assert!(!manager.is_running());
    }

    #[test]
    fn test_ebpf_daemon_stop_no_pid_file() {
        let dir = tempfile::tempdir().unwrap();
        let manager = EbpfDaemonManager {
            pid_path: dir.path().join("sevorix-ebpf.pid"),
            log_path: dir.path().join("sevorix-ebpf.log"),
        };
        let result = manager.stop();
        assert!(result.is_ok());
    }

    #[test]
    fn test_ebpf_daemon_status_no_pid_file() {
        let dir = tempfile::tempdir().unwrap();
        let manager = EbpfDaemonManager {
            pid_path: dir.path().join("sevorix-ebpf.pid"),
            log_path: dir.path().join("sevorix-ebpf.log"),
        };
        manager.status();
    }

    #[test]
    fn test_poll_pid_file_returns_none_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.pid");
        let result = poll_pid_file(&path, 1, 1);
        assert!(result.is_none());
    }

    #[test]
    fn test_poll_pid_file_returns_pid_when_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pid");
        fs::write(&path, "12345").unwrap();
        let result = poll_pid_file(&path, 3, 1);
        assert_eq!(result, Some(12345));
    }

    #[test]
    fn test_is_watchtower_running_returns_bool() {
        let _result = is_watchtower_running();
    }

    #[test]
    fn test_is_ebpf_daemon_running_returns_bool() {
        let _result = is_ebpf_daemon_running();
    }
}
