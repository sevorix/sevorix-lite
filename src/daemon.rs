// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

use anyhow::{Context, Result};
use daemonize::{Daemonize, Outcome};
use directories::{ProjectDirs, UserDirs};
use libc;
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

/// Manages Watchtower daemon lifecycle (start/stop/status).
pub struct DaemonManager {
    pid_path: PathBuf,
    log_path: PathBuf,
}

/// Manages eBPF daemon lifecycle (start/stop/status).
pub struct EbpfDaemonManager {
    pid_path: PathBuf,
    log_path: PathBuf,
}

impl DaemonManager {
    pub fn new() -> Result<Self> {
        let proj_dirs = ProjectDirs::from("com", "sevorix", "sevorix")
            .ok_or_else(|| anyhow::anyhow!("Could not determine project directories"))?;

        // Use state_dir for PID and logs. Fallback to cache_dir if state_dir not available (rare on Linux)
        let state_dir = proj_dirs
            .state_dir()
            .unwrap_or_else(|| proj_dirs.cache_dir());
        fs::create_dir_all(state_dir).context("Failed to create state directory")?;

        Ok(Self {
            pid_path: state_dir.join("sevorix.pid"),
            log_path: state_dir.join("sevorix.log"),
        })
    }

    pub fn start(&self, session_id: uuid::Uuid, start_ebpf: bool) -> Result<()> {
        if self.is_running() {
            println!(
                "Sevorix is already running (PID: {})",
                self.read_pid().unwrap_or(0)
            );
            return Err(anyhow::anyhow!("Sevorix is already running."));
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
                let wt_pid_str = wt_pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| format!("(see {})", self.pid_path.display()));

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
                println!("  Watchtower PID:  {}", wt_pid_str);
                if let Some(ref s) = ebpf_pid_str {
                    println!("  eBPF daemon PID: {}", s);
                }
                println!("  Session ID:      {}", session_id);
                println!("  Service log:     {}", self.log_path.display());
                println!("  Session log:     {}", session_log_path.display());
                println!("  Traffic log:     {}", traffic_log_path.display());
                println!("📡 API:            http://localhost:3000/analyze");
                println!("📊 Dashboard:      http://localhost:3000/dashboard/desktop.html");

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
            // Wait a bit? Assuming immediate.
            if self.pid_path.exists() {
                let _ = fs::remove_file(&self.pid_path);
            }
            println!("Sevorix stopped (PID: {})", pid);
        } else {
            println!("Sevorix is not running.");
        }
        Ok(())
    }

    pub fn status(&self) {
        if let Some(pid) = self.read_pid() {
            let res = unsafe { libc::kill(pid, 0) };
            if res == 0 {
                println!("Sevorix is running (PID: {})", pid);
                println!("PID file: {}", self.pid_path.display());
                println!("Logs: {}", self.log_path.display());
                println!("📡 API: http://localhost:3000/analyze");
                println!("📊 Dashboard: http://localhost:3000/dashboard/desktop.html");
            } else {
                println!("Sevorix PID file exists but process is gone. Cleaning up.");
                let _ = fs::remove_file(&self.pid_path);
            }
        } else {
            println!("Sevorix is NOT running.");
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

/// Check if the Watchtower daemon is running (convenience function).
pub fn is_watchtower_running() -> bool {
    DaemonManager::new()
        .map(|m| m.is_running())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_manager_new_creates_directory() {
        // DaemonManager::new() should create the state directory
        let result = DaemonManager::new();
        assert!(result.is_ok());

        let manager = result.unwrap();
        // Verify paths are set correctly
        assert!(manager.pid_path.to_string_lossy().contains("sevorix.pid"));
        assert!(manager.log_path.to_string_lossy().contains("sevorix.log"));
    }

    #[test]
    fn test_daemon_manager_pid_path_structure() {
        let manager = DaemonManager::new().unwrap();
        // PID path should end with sevorix.pid
        assert!(manager.pid_path.ends_with("sevorix.pid"));
    }

    #[test]
    fn test_daemon_manager_log_path_structure() {
        let manager = DaemonManager::new().unwrap();
        // Log path should end with sevorix.log
        assert!(manager.log_path.ends_with("sevorix.log"));
    }

    #[test]
    fn test_is_running_no_pid_file() {
        let dir = tempfile::tempdir().unwrap();
        let manager = DaemonManager {
            pid_path: dir.path().join("sevorix.pid"),
            log_path: dir.path().join("sevorix.log"),
        };
        // When no PID file exists, is_running should return false
        assert!(!manager.is_running());
    }

    #[test]
    fn test_read_pid_empty_content() {
        // Test that read_pid returns None for empty content
        let content = "";
        let result: Option<i32> = content.trim().parse().ok();
        assert!(result.is_none());
    }

    #[test]
    fn test_read_pid_valid_pid() {
        // Test that read_pid parsing works correctly
        let content = "12345";
        let result: Option<i32> = content.trim().parse().ok();
        assert_eq!(result, Some(12345));
    }

    #[test]
    fn test_read_pid_with_whitespace() {
        // Test that read_pid handles whitespace correctly
        let content = "  12345  \n";
        let result: Option<i32> = content.trim().parse().ok();
        assert_eq!(result, Some(12345));
    }

    #[test]
    fn test_read_pid_invalid_content() {
        // Test that read_pid handles invalid content
        let content = "not a pid";
        let result: Option<i32> = content.trim().parse().ok();
        assert!(result.is_none());
    }

    #[test]
    fn test_status_not_running_no_pid() {
        let manager = DaemonManager::new().unwrap();
        // status() should not panic when no PID file exists
        // It will print to stdout, we just verify it doesn't panic
        manager.status();
    }

    #[test]
    fn test_stop_no_process() {
        let manager = DaemonManager::new().unwrap();
        // stop() should not panic when no process is running
        let result = manager.stop();
        assert!(result.is_ok());
    }

    #[test]
    fn test_pid_path_is_in_state_dir() {
        let manager = DaemonManager::new().unwrap();
        // PID path should be in a state or cache directory
        let path_str = manager.pid_path.to_string_lossy();
        // Should contain sevorix somewhere in the path
        assert!(path_str.contains("sevorix"));
    }

    #[test]
    fn test_log_path_is_in_state_dir() {
        let manager = DaemonManager::new().unwrap();
        // Log path should be in a state or cache directory
        let path_str = manager.log_path.to_string_lossy();
        // Should contain sevorix somewhere in the path
        assert!(path_str.contains("sevorix"));
    }

    #[test]
    fn test_paths_are_consistent() {
        let manager = DaemonManager::new().unwrap();
        // Both paths should be in the same parent directory
        assert_eq!(manager.pid_path.parent(), manager.log_path.parent());
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
    fn test_daemon_read_pid_returns_none_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let manager = DaemonManager {
            pid_path: dir.path().join("sevorix.pid"),
            log_path: dir.path().join("sevorix.log"),
        };
        assert!(manager.read_pid().is_none());
    }

    #[test]
    fn test_daemon_read_pid_returns_value_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("sevorix.pid");
        fs::write(&pid_path, "99999").unwrap();
        let manager = DaemonManager {
            pid_path,
            log_path: dir.path().join("sevorix.log"),
        };
        assert_eq!(manager.read_pid(), Some(99999));
    }

    #[test]
    fn test_daemon_read_pid_returns_none_for_invalid_content() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("sevorix.pid");
        fs::write(&pid_path, "not-a-pid").unwrap();
        let manager = DaemonManager {
            pid_path,
            log_path: dir.path().join("sevorix.log"),
        };
        assert!(manager.read_pid().is_none());
    }

    #[test]
    fn test_daemon_stop_no_pid_file() {
        let dir = tempfile::tempdir().unwrap();
        let manager = DaemonManager {
            pid_path: dir.path().join("sevorix.pid"),
            log_path: dir.path().join("sevorix.log"),
        };
        // Should not error when there's no PID file
        let result = manager.stop();
        assert!(result.is_ok());
    }

    #[test]
    fn test_daemon_status_no_pid_file() {
        let dir = tempfile::tempdir().unwrap();
        let manager = DaemonManager {
            pid_path: dir.path().join("sevorix.pid"),
            log_path: dir.path().join("sevorix.log"),
        };
        // Should not panic when there's no PID file
        manager.status();
    }

    #[test]
    fn test_ebpf_daemon_read_pid_returns_none_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let manager = EbpfDaemonManager {
            pid_path: dir.path().join("sevorix-ebpf.pid"),
            log_path: dir.path().join("sevorix-ebpf.log"),
        };
        assert!(manager.read_pid().is_none());
    }

    #[test]
    fn test_ebpf_daemon_read_pid_returns_value_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("sevorix-ebpf.pid");
        fs::write(&pid_path, "88888").unwrap();
        let manager = EbpfDaemonManager {
            pid_path,
            log_path: dir.path().join("sevorix-ebpf.log"),
        };
        assert_eq!(manager.read_pid(), Some(88888));
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
        // Should not panic
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
        // is_watchtower_running should return a bool without panicking
        let _result = is_watchtower_running();
    }

    #[test]
    fn test_is_ebpf_daemon_running_returns_bool() {
        // is_ebpf_daemon_running should return a bool without panicking
        let _result = is_ebpf_daemon_running();
    }
}
