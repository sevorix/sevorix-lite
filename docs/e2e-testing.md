# E2E Testing Framework

This document describes the end-to-end test suite for Sevorix Watchtower — how it is organized, how to run it, how to write new tests, and how it integrates with CI.

## Architecture Overview

The e2e suite lives in `tests/` and is split across 13 test binary files (one per scenario group). All tests share a common harness in `tests/common/`.

```
tests/
├── common/
│   ├── mod.rs          # Re-exports: harness, upstream, ws_client
│   ├── harness.rs      # TestHarness — in-process Axum server + reqwest client
│   ├── upstream.rs     # MockUpstream — fake HTTP target for proxy tests
│   └── ws_client.rs    # WsClient — WebSocket event capture helper
├── e2e_analyze.rs      # Scenarios 2.x — /analyze endpoint
├── e2e_cli.rs          # Scenarios 8.x — CLI subcommands (validate, config, --help)
├── e2e_dashboard.rs    # Scenarios 7.x — Dashboard HTML, REST APIs
├── e2e_edge_cases.rs   # Scenarios 13.x — Error handling, malformed input
├── e2e_integrations.rs # Scenarios 9.x — integrations subcommand
├── e2e_intervention.rs # Scenarios 3.x — Human-in-the-loop / PENDING flow
├── e2e_layers.rs       # Scenarios 15.x — Multi-layer classification
├── e2e_logging.rs      # Scenarios 12.x — Traffic log JSONL
├── e2e_performance.rs  # Scenarios 14.x — Latency contracts
├── e2e_policy_engine.rs # Scenarios 4.x — Policy match types
├── e2e_proxy.rs        # Scenarios 1.x — HTTP proxy mode
├── e2e_roles.rs        # Scenarios 5.x — Role system
└── e2e_websocket.rs    # Scenarios 6.x — WebSocket live feed
```

### Key Design Principles

**In-process servers, not daemon processes.** Every test that exercises the HTTP API binds an Axum server to `0.0.0.0:0` (OS-assigned port) in the same process. This means:
- Tests run fully in parallel with no port conflicts.
- No `~/.sevorix/` state is read or written — each test gets a fresh `TempDir`.
- No `cargo build` step needed before running library tests.

**CLI tests use the installed binary.** `e2e_cli.rs` and `e2e_integrations.rs` spawn the real `sevorix` binary. The `sevorix_bin()` helper checks `target/debug/sevorix`, then `target/release/sevorix`, then falls back to `sevorix` on `$PATH`. Ensure the binary is built (`cargo build`) or installed (`./install.sh`) before running these two test files.

## Test Harness (`tests/common/harness.rs`)

`TestHarness` is the core abstraction for HTTP API tests.

### Constructors

| Constructor | When to use |
|---|---|
| `TestHarness::new().await` | No role configured — tests fail-closed behavior |
| `TestHarness::with_role(Some("name".to_string())).await` | Sets `current_role`; pair with `add_role_direct()` |
| `TestHarness::with_timeout(secs, allow_on_timeout).await` | Override intervention timeout for 3.x tests |

### Adding Policies and Roles

Do **not** write JSON files into the TempDir and call the reload endpoint — the reload handler loads from `~/.sevorix/`, not the TempDir. Instead, mutate the in-memory engine directly:

```rust
h.add_policy_direct(Policy {
    id: "block-drop".to_string(),
    match_type: PolicyType::Simple("DROP TABLE".to_string()),
    action: Action::Block,
    context: PolicyContext::All,
    kill: false,
});
h.add_role_direct(Role {
    name: "test".to_string(),
    policies: vec!["block-drop".to_string()],
    is_dynamic: false,
});
```

### Making Requests

```rust
// POST /analyze
let resp = h.client
    .post(format!("{}/analyze", h.base_url()))
    .json(&json!({"payload": "DROP TABLE users", "context": "Shell"}))
    .send().await.unwrap()
    .json::<serde_json::Value>().await.unwrap();
assert_eq!(resp["status"], "BLOCK");

// GET /health
let resp = h.client.get(format!("{}/health", h.base_url())).send().await.unwrap();
assert_eq!(resp.status(), 200);
```

## WebSocket Client (`tests/common/ws_client.rs`)

`WsClient` captures real-time events for intervention and WebSocket tests.

```rust
let mut ws = WsClient::connect(h.addr).await;

// Block until a matching event arrives (or timeout)
let pending = ws.wait_for_event(
    |e| e["type"] == "PENDING",
    Duration::from_secs(5),
).await.expect("should receive PENDING event");

let event_id = pending["event_id"].as_str().unwrap();

// Non-blocking drain of all queued events
let events = ws.drain();
```

## Mock Upstream (`tests/common/upstream.rs`)

`MockUpstream` provides a fake HTTP server for proxy tests (scenarios 1.x).

```rust
let upstream = MockUpstream::start_any().await;  // catches all methods/paths

// Configure the proxied reqwest client
let proxied_client = reqwest::Client::builder()
    .proxy(reqwest::Proxy::all(h.base_url()).unwrap())
    .build()
    .unwrap();

let resp = proxied_client
    .get(upstream.uri())
    .send().await.unwrap();

upstream.assert_called();         // at least 1 request
upstream.assert_received(3);      // exactly 3 requests
upstream.assert_not_called();     // zero requests
```

## Running Tests

### All e2e suites

```bash
cargo build                           # required for CLI tests
cargo test --test 'e2e_*'            # all 13 suites in parallel
```

### Individual suite

```bash
cargo test --test e2e_analyze
cargo test --test e2e_proxy
cargo test --test e2e_intervention
cargo test --test e2e_policy_engine
cargo test --test e2e_roles
cargo test --test e2e_websocket
cargo test --test e2e_dashboard
cargo test --test e2e_cli
cargo test --test e2e_integrations
cargo test --test e2e_logging
cargo test --test e2e_edge_cases
cargo test --test e2e_performance
cargo test --test e2e_layers
```

### Single test by name

```bash
cargo test --test e2e_analyze test_2_1_block_red_lane
```

### With output (useful for debugging)

```bash
cargo test --test e2e_intervention -- --nocapture
```

### With `pro` feature

```bash
cargo test --test 'e2e_*' --features pro
```

## Writing a New Test

### HTTP API test (typical case)

```rust
// tests/e2e_my_feature.rs
mod common;
use common::harness::TestHarness;
use sevorix_watchtower::policy::{Action, Policy, PolicyContext, PolicyType, Role};
use serde_json::json;

#[tokio::test]
async fn test_my_scenario() {
    // 1. Create harness with a role
    let h = TestHarness::with_role(Some("test".to_string())).await;

    // 2. Register policies and the role
    h.add_policy_direct(Policy {
        id: "my-policy".to_string(),
        match_type: PolicyType::Simple("DANGER".to_string()),
        action: Action::Block,
        context: PolicyContext::All,
        kill: false,
    });
    h.add_role_direct(Role {
        name: "test".to_string(),
        policies: vec!["my-policy".to_string()],
        is_dynamic: false,
    });

    // 3. Send request and assert
    let resp = h.client
        .post(format!("{}/analyze", h.base_url()))
        .json(&json!({"payload": "DANGER zone", "context": "Shell"}))
        .send().await.unwrap()
        .json::<serde_json::Value>().await.unwrap();

    assert_eq!(resp["status"], "BLOCK");
}
```

### CLI test (needs binary on disk)

```rust
// tests/e2e_my_cli.rs
use std::process::Command;

fn sevorix_bin() -> std::path::PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    for profile in &["debug", "release"] {
        let p = std::path::Path::new(manifest_dir)
            .join("target").join(profile).join("sevorix");
        if p.exists() { return p; }
    }
    std::path::PathBuf::from("sevorix")
}

#[test]
fn test_my_cli_command() {
    let output = Command::new(sevorix_bin())
        .args(["validate", "DROP TABLE", "-C", "Shell"])
        .output()
        .expect("failed to run sevorix");

    assert_eq!(output.status.code(), Some(1));  // BLOCK → exit 1
}
```

### Intervention test (needs WsClient)

```rust
#[tokio::test]
async fn test_operator_allows_flagged() {
    let h = /* harness with Flag policy */;
    let mut ws = WsClient::connect(h.addr).await;

    // Start analyze in background (it will block waiting for intervention)
    let task = tokio::spawn({
        let client = h.client.clone();
        let base = h.base_url();
        async move {
            client.post(format!("{}/analyze", base))
                .json(&json!({"payload": "FLAGGED_CONTENT", "context": "Shell"}))
                .send().await.unwrap()
                .json::<serde_json::Value>().await.unwrap()
        }
    });

    // Wait for PENDING, then decide
    let pending = ws.wait_for_event(|e| e["type"] == "PENDING", Duration::from_secs(5))
        .await.unwrap();
    h.client.post(format!("{}/api/decide", h.base_url()))
        .json(&json!({"event_id": pending["event_id"], "action": "allow"}))
        .send().await.unwrap();

    let result = timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
    assert_eq!(result["status"], "ALLOW");
}
```

## Fail-Closed Behavior

Two invariants every test author must know:

1. **No role → BLOCK.** Both `/analyze` and the proxy handler return `BLOCK` if `current_role` is `None` or if the named role is not registered in the policy engine. Use `TestHarness::new()` only when testing this behavior explicitly.

2. **`add_role_direct` must match `with_role`.** If you call `TestHarness::with_role(Some("test"))`, you must also call `h.add_role_direct(Role { name: "test", ... })` before sending requests, or all requests will BLOCK.

## Test-to-Scenario Map

| File | Scenarios | Count |
|---|---|---|
| `e2e_proxy.rs` | 1.1–1.5 Proxy passthrough, BLOCK 403, concurrency | 5 |
| `e2e_analyze.rs` | 2.1–2.9 /analyze BLOCK/ALLOW/FLAG, context/role scoping | 9 |
| `e2e_intervention.rs` | 3.1–3.9 PENDING/DECIDED flow, timeouts, invalid event_id | 6 |
| `e2e_policy_engine.rs` | 4.1–4.6 Simple/Regex/Executable match, precedence | 6 |
| `e2e_roles.rs` | 5.1–5.6 Role subset, unknown role, set-role, log field | 6 |
| `e2e_websocket.rs` | 6.1–6.7 ALLOW/BLOCK events, multi-subscriber, late join | 7 |
| `e2e_dashboard.rs` | 7.1–7.10 HTML, redirect, events API, stats, sessions | 8 |
| `e2e_cli.rs` | 8.6–8.9 validate, config check, --help | 9 |
| `e2e_integrations.rs` | 9.1–9.10 list, alias, install, uninstall, status | 16 |
| `e2e_logging.rs` | 12.1–12.4 JSONL schema, role field, file survives | 4 |
| `e2e_edge_cases.rs` | 13.x No policies, malformed policy file, binary payload | 6 |
| `e2e_performance.rs` | 14.x Green <50ms, Red <20ms, Yellow holds | 4 |
| `e2e_layers.rs` | 15.x Shell/network layer events, /api/events?layer= | 3 |

**Total: 89 tests across 13 suites.**

## CI Integration

E2E tests run as part of the standard `cargo test --workspace` job in `.github/workflows/ci.yml`. A separate `.github/workflows/e2e.yml` workflow runs only the e2e suites with an explicit `cargo build` step first (required for `e2e_cli` and `e2e_integrations` which spawn the binary):

```bash
# What CI runs:
cargo build                    # build sevorix binary for CLI tests
cargo test --test 'e2e_*'     # all 13 e2e suites
```

Tests that require a live daemon (daemon lifecycle: start/stop/restart) are intentionally excluded from CI and from this suite — they cannot run safely in parallel with other tests or with a live daemon.

## Dependencies

Dev-dependencies added for this suite (in `Cargo.toml`):

| Crate | Purpose |
|---|---|
| `tempfile` | Isolated TempDir per test |
| `wiremock` | Mock HTTP upstream for proxy tests |
| `tokio-tungstenite` | WebSocket client in WsClient |
| `futures-util` | Stream utilities for tungstenite |
