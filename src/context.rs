// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

use crate::settings::ContextSettings;
use anyhow::Context as _;
use base64;
use base64::Engine;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};
use std::{
    collections::{HashMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};
use zstd::stream::{encode_all as zstd_encode_all, read::Decoder as ZstdDecoder};

pub const DEFAULT_CONTEXT_RING_BUFFER_SIZE: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ContextStream {
    Stdin,
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContextChunk {
    pub session_id: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub stream: ContextStream,
    pub raw: String,
    /// If compressed, base64-encoded compressed payload (zstd)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_b64: Option<String>,
    /// Compression codec used, e.g. "zstd"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compressed: Option<String>,
    /// Original raw length before compression
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_len: Option<u64>,
    pub text: String,
    pub seq: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContextChunkInput {
    pub source: String,
    pub stream: ContextStream,
    pub raw: String,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextQueryResult {
    pub chunks: Vec<ContextChunk>,
    pub total: usize,
}

#[derive(Debug, Default)]
struct SessionContext {
    next_seq: u64,
    chunks: VecDeque<ContextChunk>,
    total_bytes: u64,
    last_updated: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct ContextStore {
    root_dir: PathBuf,
    max_chunks: usize,
    sessions: Mutex<HashMap<String, Arc<Mutex<SessionContext>>>>,
    settings: Arc<ContextSettings>,
}

impl ContextStore {
    pub fn new<P: AsRef<Path>>(
        root_dir: P,
        max_chunks: usize,
        settings: Arc<ContextSettings>,
    ) -> anyhow::Result<Self> {
        let root_dir = root_dir.as_ref().to_path_buf();
        fs::create_dir_all(&root_dir)
            .with_context(|| format!("creating context dir {}", root_dir.display()))?;

        let mut sessions = HashMap::new();

        for entry in fs::read_dir(&root_dir)
            .with_context(|| format!("reading context dir {}", root_dir.display()))?
        {
            let Ok(entry) = entry else {
                continue;
            };
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
                continue;
            }

            let Ok(file) = File::open(&path) else {
                continue;
            };
            let mut session = SessionContext::default();

            // Load chunks and compute next_seq; track file size as stored bytes
            for line in BufReader::new(file).lines().map_while(Result::ok) {
                let Ok(chunk) = serde_json::from_str::<ContextChunk>(&line) else {
                    continue;
                };
                session.next_seq = session.next_seq.max(chunk.seq.saturating_add(1));
                push_chunk(&mut session.chunks, chunk, max_chunks);
            }

            // Use on-disk file size as the stored bytes for this session
            session.total_bytes = path.metadata().map(|m| m.len()).unwrap_or(0);
            session.last_updated = Some(Utc::now());

            let Some(session_id) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };

            sessions.insert(session_id.to_string(), Arc::new(Mutex::new(session)));
        }

        Ok(Self {
            root_dir,
            max_chunks,
            sessions: Mutex::new(sessions),
            settings,
        })
    }

    pub fn append_chunks(
        &self,
        session_id: &str,
        chunks: Vec<ContextChunkInput>,
    ) -> anyhow::Result<Vec<ContextChunk>> {
        if chunks.is_empty() {
            return Ok(Vec::new());
        }

        // Acquire (or create) the per-session state arc, then lock it.
        let session_arc = {
            let mut sessions_map = self
                .sessions
                .lock()
                .expect("context store session mutex poisoned");
            sessions_map
                .entry(session_id.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(SessionContext::default())))
                .clone()
        };

        // Use injected settings (cheap, deterministic)
        let ctx_settings = &*self.settings;

        let compress_enabled = ctx_settings.clone().compress_enabled.unwrap_or(true);
        let compression_threshold = ctx_settings
            .compression_threshold
            .as_deref()
            .and_then(ContextSettings::parse_size_to_bytes)
            .unwrap_or(4 * 1024);
        let max_chunk_bytes = ctx_settings
            .max_chunk_bytes
            .as_deref()
            .and_then(ContextSettings::parse_size_to_bytes)
            .unwrap_or(1024 * 1024);

        let mut stored: Vec<ContextChunk> = Vec::with_capacity(chunks.len());

        let path = self.session_path(session_id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating context parent dir {}", parent.display()))?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening context file {}", path.display()))?;

        for chunk in &stored {
            let line =
                serde_json::to_string(chunk).context("serializing context chunk for JSONL")?;
            writeln!(file, "{line}")
                .with_context(|| format!("writing context chunk to {}", path.display()))?;
        }
        file.flush().ok();

        // Ensure the append file is closed before any atomic rewrite
        drop(file);

        // Refresh session stored size from on-disk file size and update in-memory
        {
            let mut session = session_arc.lock().expect("session mutex poisoned");

            // Build stored chunks while holding the per-session lock so seq numbers are unique
            let base_seq = session.next_seq;
            for (idx, chunk) in chunks.into_iter().enumerate() {
                let timestamp = chunk.timestamp.unwrap_or_else(Utc::now);
                let original_len = chunk.raw.len();

                // Truncate raw payload to max_chunk_bytes if necessary (preserve UTF-8 lossily)
                let raw_bytes = chunk.raw.into_bytes();
                let truncated = if raw_bytes.len() > max_chunk_bytes as usize {
                    String::from_utf8_lossy(&raw_bytes[..max_chunk_bytes as usize]).to_string()
                } else {
                    String::from_utf8_lossy(&raw_bytes).to_string()
                };

                // Decide whether to compress (based on original length before truncation)
                let mut raw_b64 = None;
                let mut compressed_codec = None;
                if compress_enabled
                    && (compression_threshold == 0 || original_len as u64 >= compression_threshold)
                {
                    if let Ok((b64, _len)) = compress_raw_to_base64(&truncated) {
                        raw_b64 = Some(b64);
                        compressed_codec = Some("zstd".to_string());
                    }
                }

                let stored_chunk = ContextChunk {
                    session_id: session_id.to_string(),
                    timestamp,
                    source: chunk.source,
                    stream: chunk.stream,
                    raw: truncated.clone(),
                    raw_b64,
                    compressed: compressed_codec,
                    raw_len: Some(original_len as u64),
                    text: strip_ansi(&truncated),
                    seq: base_seq + idx as u64,
                };
                stored.push(stored_chunk);
            }

            // Append to on-disk JSONL while still holding the session lock to preserve ordering
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .with_context(|| format!("opening context file {}", path.display()))?;

            for chunk in &stored {
                let line =
                    serde_json::to_string(chunk).context("serializing context chunk for JSONL")?;
                writeln!(file, "{line}")
                    .with_context(|| format!("writing context chunk to {}", path.display()))?;
            }
            file.flush().ok();

            // Refresh session stored size from on-disk file size
            session.total_bytes = path
                .metadata()
                .map(|m| m.len())
                .unwrap_or(session.total_bytes);
            session.last_updated = Some(Utc::now());

            session.next_seq += stored.len() as u64;
            for chunk in stored.iter().cloned() {
                push_chunk(&mut session.chunks, chunk, self.max_chunks);
            }

            // Per-session eviction: if configured, drop oldest chunks until under cap
            if let Some(per_session_cap_str) = &ctx_settings.per_session_cap {
                if let Some(per_session_cap) =
                    ContextSettings::parse_size_to_bytes(per_session_cap_str)
                {
                    while session.total_bytes > per_session_cap && !session.chunks.is_empty() {
                        session.chunks.pop_front();
                    }

                    // Rewrite session file atomically with remaining chunks
                    let tmp_path = path.with_extension("jsonl.tmp");
                    let mut tmp = OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(&tmp_path)
                        .with_context(|| {
                            format!("writing tmp context file {}", tmp_path.display())
                        })?;
                    for c in session.chunks.iter() {
                        let line = serde_json::to_string(c)
                            .context("serializing context chunk for JSONL")?;
                        writeln!(tmp, "{line}")?;
                    }
                    tmp.flush().ok();
                    let new_len = tmp.metadata().map(|m| m.len()).unwrap_or(0);
                    std::fs::rename(&tmp_path, &path).with_context(|| {
                        format!("atomic rename {} -> {}", tmp_path.display(), path.display())
                    })?;
                    session.total_bytes = new_len;
                    session.last_updated = Some(Utc::now());
                }
            }
        }

        // Global eviction: if global_cap is set, evict whole sessions by oldest_first
        if let Some(global_cap_str) = &ctx_settings.global_cap {
            if let Some(global_cap) = ContextSettings::parse_size_to_bytes(global_cap_str) {
                // compute total across sessions
                let mut sessions_map = self
                    .sessions
                    .lock()
                    .expect("context store session mutex poisoned");
                let mut total: u64 = sessions_map
                    .values()
                    .map(|s_arc| s_arc.lock().map(|s| s.total_bytes).unwrap_or(0))
                    .sum();
                if total > global_cap {
                    // build a vec of (session_id, last_updated, bytes)
                    let mut list: Vec<(String, Option<DateTime<Utc>>, u64)> = sessions_map
                        .iter()
                        .map(|(id, s_arc)| {
                            let guard = s_arc.lock().ok();
                            let lu = guard.as_ref().and_then(|g| g.last_updated);
                            let bytes = guard.as_ref().map(|g| g.total_bytes).unwrap_or(0);
                            (id.clone(), lu, bytes)
                        })
                        .collect();
                    // sort by last_updated ascending (oldest first)
                    list.sort_by_key(|(_, lu, _)| lu.map(|d| d.timestamp()).unwrap_or(0));

                    for (sid, _lu, sbytes) in list {
                        if total <= global_cap {
                            break;
                        }
                        // remove session file and in-memory entry
                        let s_path = self.session_path(&sid);
                        let _ = std::fs::remove_file(&s_path);
                        if sessions_map.remove(&sid).is_some() {
                            total = total.saturating_sub(sbytes);
                        }
                    }
                }
            }
        }

        Ok(stored)
    }

    pub fn query(
        &self,
        session_id: &str,
        limit: usize,
        offset: usize,
        stream: Option<ContextStream>,
    ) -> anyhow::Result<ContextQueryResult> {
        let path = self.session_path(session_id);
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ContextQueryResult {
                    chunks: Vec::new(),
                    total: 0,
                });
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("opening context file {}", path.display()));
            }
        };

        let mut filtered = Vec::new();
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            let Ok(chunk) = serde_json::from_str::<ContextChunk>(&line) else {
                continue;
            };
            if chunk.session_id != session_id {
                continue;
            }
            if stream
                .as_ref()
                .is_some_and(|wanted| wanted != &chunk.stream)
            {
                continue;
            }
            filtered.push(chunk);
        }

        let total = filtered.len();
        let chunks = filtered.into_iter().skip(offset).take(limit).collect();
        Ok(ContextQueryResult { chunks, total })
    }

    pub fn recent_chunks(
        &self,
        session_id: &str,
        limit: usize,
        stream: Option<ContextStream>,
    ) -> Vec<ContextChunk> {
        let sessions = self
            .sessions
            .lock()
            .expect("context store session mutex poisoned");
        let Some(session_arc) = sessions.get(session_id) else {
            return Vec::new();
        };
        let session = session_arc.lock().expect("session mutex poisoned");

        let mut collected: Vec<ContextChunk> = session
            .chunks
            .iter()
            .filter(|chunk| match stream.as_ref() {
                Some(wanted) => wanted == &chunk.stream,
                None => true,
            })
            .cloned()
            .collect();

        if collected.len() > limit {
            let drain_len = collected.len() - limit;
            collected.drain(0..drain_len);
        }

        collected
    }

    pub fn session_path(&self, session_id: &str) -> PathBuf {
        self.root_dir.join(format!("{session_id}.jsonl"))
    }
}

pub fn default_context_dir() -> PathBuf {
    directories::UserDirs::new()
        .map(|dirs| dirs.home_dir().join(".sevorix").join("context"))
        .unwrap_or_else(|| PathBuf::from(".sevorix/context"))
}

pub fn strip_ansi(raw: &str) -> String {
    static ANSI_REGEX: OnceLock<Regex> = OnceLock::new();
    ANSI_REGEX
        .get_or_init(|| Regex::new(r"\x1b\[[0-9;?]*m").expect("valid ANSI strip regex"))
        .replace_all(raw, "")
        .into_owned()
}

fn push_chunk(chunks: &mut VecDeque<ContextChunk>, chunk: ContextChunk, max_chunks: usize) {
    chunks.push_back(chunk);
    while chunks.len() > max_chunks {
        chunks.pop_front();
    }
}

/// Compress a UTF-8 string with zstd (level 1) and return base64-encoded bytes
pub fn compress_raw_to_base64(raw: &str) -> anyhow::Result<(String, usize)> {
    // zstd::stream::encode_all accepts any Read; use a cursor
    let cursor = Cursor::new(raw.as_bytes());
    let compressed = zstd_encode_all(cursor, 1).context("compressing with zstd")?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&compressed);
    Ok((encoded, compressed.len()))
}

/// Decompress a base64-encoded zstd payload back to a UTF-8 string
pub fn decompress_base64_to_raw(b64: &str) -> anyhow::Result<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .context("decoding base64")?;
    let mut decoder = ZstdDecoder::new(Cursor::new(bytes)).context("zstd decoder init")?;
    let mut out = String::new();
    decoder
        .read_to_string(&mut out)
        .context("zstd decode to string")?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_chunk(source: &str, raw: &str, stream: ContextStream) -> ContextChunkInput {
        ContextChunkInput {
            source: source.to_string(),
            stream,
            raw: raw.to_string(),
            text: None,
            timestamp: None,
        }
    }

    #[test]
    fn test_strip_ansi_removes_color_codes() {
        let raw = "\u{1b}[31merror\u{1b}[0m plain";
        assert_eq!(strip_ansi(raw), "error plain");
    }

    #[test]
    fn test_append_chunks_persists_jsonl() {
        let dir = tempdir().unwrap();
        let store =
            ContextStore::new(dir.path(), 10, Arc::new(ContextSettings::default())).unwrap();

        let stored = store
            .append_chunks(
                "session-a",
                vec![sample_chunk(
                    "codex",
                    "\u{1b}[32mhello\u{1b}[0m",
                    ContextStream::Stdout,
                )],
            )
            .unwrap();

        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].seq, 0);
        assert_eq!(stored[0].text, "hello");

        let persisted = std::fs::read_to_string(store.session_path("session-a")).unwrap();
        assert!(persisted.contains("\"session_id\":\"session-a\""));
        assert!(persisted.contains("\"seq\":0"));
    }

    #[test]
    fn test_query_supports_limit_offset_and_stream() {
        let dir = tempdir().unwrap();
        let store =
            ContextStore::new(dir.path(), 10, Arc::new(ContextSettings::default())).unwrap();
        store
            .append_chunks(
                "session-a",
                vec![
                    sample_chunk("codex", "in-1", ContextStream::Stdin),
                    sample_chunk("codex", "out-1", ContextStream::Stdout),
                    sample_chunk("codex", "out-2", ContextStream::Stdout),
                ],
            )
            .unwrap();

        let queried = store
            .query("session-a", 1, 1, Some(ContextStream::Stdout))
            .unwrap();

        assert_eq!(queried.total, 2);
        assert_eq!(queried.chunks.len(), 1);
        assert_eq!(queried.chunks[0].raw, "out-2");
    }

    #[test]
    fn test_append_chunks_canonicalizes_text_from_raw() {
        let dir = tempdir().unwrap();
        let store =
            ContextStore::new(dir.path(), 10, Arc::new(ContextSettings::default())).unwrap();
        let stored = store
            .append_chunks(
                "session-a",
                vec![ContextChunkInput {
                    source: "codex".to_string(),
                    stream: ContextStream::Stdout,
                    raw: "\u{1b}[31mserver-truth\u{1b}[0m".to_string(),
                    text: Some("client-supplied".to_string()),
                    timestamp: None,
                }],
            )
            .unwrap();

        assert_eq!(stored[0].text, "server-truth");
    }

    #[test]
    fn test_ring_buffer_evicts_oldest_chunks() {
        let dir = tempdir().unwrap();
        let store = ContextStore::new(dir.path(), 2, Arc::new(ContextSettings::default())).unwrap();
        store
            .append_chunks(
                "session-a",
                vec![
                    sample_chunk("codex", "first", ContextStream::Stdout),
                    sample_chunk("codex", "second", ContextStream::Stdout),
                    sample_chunk("codex", "third", ContextStream::Stdout),
                ],
            )
            .unwrap();

        let recent = store.recent_chunks("session-a", 10, None);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].raw, "second");
        assert_eq!(recent[1].raw, "third");
    }

    #[test]
    fn test_store_loads_existing_jsonl_on_restart() {
        // Some CI/test harnesses run tests in parallel; this test depends on
        // deterministic process-global state during startup. To avoid flakes
        // we re-run the real test body in a child process with
        // `RUST_TEST_THREADS=1` so it always runs single-threaded.
        if std::env::var("SEVORIX_TEST_CHILD").is_ok() {
            let dir = tempdir().unwrap();
            {
                let store =
                    ContextStore::new(dir.path(), 2, Arc::new(ContextSettings::default())).unwrap();
                store
                    .append_chunks(
                        "session-a",
                        vec![
                            sample_chunk("codex", "first", ContextStream::Stdout),
                            sample_chunk("codex", "second", ContextStream::Stdout),
                            sample_chunk("codex", "third", ContextStream::Stdout),
                        ],
                    )
                    .unwrap();
            }

            let reloaded =
                ContextStore::new(dir.path(), 2, Arc::new(ContextSettings::default())).unwrap();
            let recent = reloaded.recent_chunks("session-a", 10, None);
            assert_eq!(recent.len(), 2);
            assert_eq!(recent[0].seq, 1);
            assert_eq!(recent[1].seq, 2);

            let appended = reloaded
                .append_chunks(
                    "session-a",
                    vec![sample_chunk("codex", "fourth", ContextStream::Stdout)],
                )
                .unwrap();
            assert_eq!(appended[0].seq, 3);

            return;
        }

        // Spawn child test run with single test thread
        let exe = std::env::current_exe().expect("current exe");
        let mut cmd = std::process::Command::new(exe);
        cmd.env("RUST_TEST_THREADS", "1");
        cmd.env("SEVORIX_TEST_CHILD", "1");
        cmd.arg("--exact");
        cmd.arg("context::tests::test_store_loads_existing_jsonl_on_restart");
        cmd.arg("--nocapture");
        let status = cmd
            .status()
            .expect("failed to spawn child process for single-threaded test");
        assert!(status.success(), "child test process failed");
    }

    #[test]
    fn test_per_session_eviction_truncates_oldest_chunks() {
        use std::env;

        // Create a settings file in a temp home and run the actual test body
        // in a child process with `SEVORIX_SETTINGS_PATH` set so we don't mutate
        // the parent process environment watched by other tests.
        let dir = tempdir().unwrap();
        let home = tempdir().unwrap();
        let settings_dir = home.path().join(".sevorix");
        std::fs::create_dir_all(&settings_dir).unwrap();
        let settings = r#"{ "context": { "per_session_cap": "300B", "compress_enabled": false } }"#;
        std::fs::write(settings_dir.join("settings.json"), settings).unwrap();
        let settings_path = settings_dir.join("settings.json");

        if std::env::var("SEVORIX_TEST_CHILD").is_ok() {
            let loaded = crate::settings::Settings::load();
            let ctx = Arc::new(loaded.context.unwrap_or_default());
            let store = ContextStore::new(dir.path(), 100, ctx).unwrap();
            // Each chunk ~200 bytes (approx). Appending 3 should exceed 300B and trigger eviction.
            let big = "x".repeat(200);
            store
                .append_chunks(
                    "s1",
                    vec![
                        ContextChunkInput {
                            source: "a".into(),
                            stream: ContextStream::Stdout,
                            raw: big.clone(),
                            text: None,
                            timestamp: None,
                        },
                        ContextChunkInput {
                            source: "a".into(),
                            stream: ContextStream::Stdout,
                            raw: big.clone(),
                            text: None,
                            timestamp: None,
                        },
                        ContextChunkInput {
                            source: "a".into(),
                            stream: ContextStream::Stdout,
                            raw: big.clone(),
                            text: None,
                            timestamp: None,
                        },
                    ],
                )
                .unwrap();

            // After eviction, remaining chunks should be <= cap; at least oldest should be removed.
            let recent = store.recent_chunks("s1", 10, None);
            assert!(recent.len() < 3);
            return;
        }

        let exe = std::env::current_exe().expect("current exe");
        let mut cmd = std::process::Command::new(exe);
        cmd.env("RUST_TEST_THREADS", "1");
        cmd.env("SEVORIX_TEST_CHILD", "1");
        cmd.env("SEVORIX_SETTINGS_PATH", settings_path);
        cmd.arg("--exact");
        cmd.arg("context::tests::test_per_session_eviction_truncates_oldest_chunks");
        let status = cmd.status().expect("failed to spawn child process");
        assert!(status.success());
    }

    #[test]
    fn test_global_eviction_removes_whole_sessions_oldest_first() {
        use std::env;

        let dir = tempdir().unwrap();
        // Setup a settings file and run the test body in a child process so we don't
        // mutate parent process env while other tests run.
        let home = tempdir().unwrap();
        let settings_dir = home.path().join(".sevorix");
        std::fs::create_dir_all(&settings_dir).unwrap();
        let settings = r#"{ "context": { "global_cap": "350B", "compress_enabled": false } }"#;
        std::fs::write(settings_dir.join("settings.json"), settings).unwrap();
        let settings_path = settings_dir.join("settings.json");

        if std::env::var("SEVORIX_TEST_CHILD").is_ok() {
            let loaded = crate::settings::Settings::load();
            let ctx = Arc::new(loaded.context.unwrap_or_default());
            let store = ContextStore::new(dir.path(), 100, ctx).unwrap();

            let small = "y".repeat(200);

            // Append to session A first
            store
                .append_chunks(
                    "A",
                    vec![ContextChunkInput {
                        source: "x".into(),
                        stream: ContextStream::Stdout,
                        raw: small.clone(),
                        text: None,
                        timestamp: None,
                    }],
                )
                .unwrap();

            // Append to session B later
            store
                .append_chunks(
                    "B",
                    vec![ContextChunkInput {
                        source: "x".into(),
                        stream: ContextStream::Stdout,
                        raw: small.clone(),
                        text: None,
                        timestamp: None,
                    }],
                )
                .unwrap();

            // Recreate store to trigger load path
            let _reloaded =
                ContextStore::new(dir.path(), 100, Arc::new(ContextSettings::default())).unwrap();

            let a_path = dir.path().join("A.jsonl");
            let b_path = dir.path().join("B.jsonl");
            let a_exists = a_path.exists();
            let b_exists = b_path.exists();

            assert!(
                !(a_exists && b_exists),
                "At least one session should have been evicted"
            );
            return;
        }

        let exe = std::env::current_exe().expect("current exe");
        let mut cmd = std::process::Command::new(exe);
        cmd.env("RUST_TEST_THREADS", "1");
        cmd.env("SEVORIX_TEST_CHILD", "1");
        cmd.env("SEVORIX_SETTINGS_PATH", settings_path);
        cmd.arg("--exact");
        cmd.arg("context::tests::test_global_eviction_removes_whole_sessions_oldest_first");
        let status = cmd.status().expect("failed to spawn child process");
        assert!(status.success());
    }
}

#[test]
fn test_zstd_compress_decompress_roundtrip() {
    let raw = "This is a test payload with some repeated text. ";
    let mut repeated = String::new();
    for _ in 0..100 {
        repeated.push_str(raw);
    }

    let (b64, compressed_len) = compress_raw_to_base64(&repeated).expect("compress");
    assert!(compressed_len > 0);
    let decompressed = decompress_base64_to_raw(&b64).expect("decompress");
    assert_eq!(decompressed, repeated);
}
