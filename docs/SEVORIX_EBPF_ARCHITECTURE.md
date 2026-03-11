# Sevorix eBPF Architecture Design

## Problem Statement

The goal: **Intercept all syscalls, network calls, and shell commands, evaluate them against policy, and either accept or reject them.**

This should work for both:
- **Interactive mode**: `sevsh` - interactive shell with monitoring
- **Non-interactive mode**: `sevorix exec <command>` - single command execution

## Why seccomp-unotify Failed

### The Fundamental Problem

seccomp-unotify has a **synchronous notification model** that fundamentally conflicts with complex policy evaluation:

```
┌─────────────────┐     syscall      ┌─────────────────┐
│   Application   │ ──────────────────│   Kernel         │
│   (traced)      │                    │   seccomp        │
│                 │     block         │   filter          │
│                 │ ◄─────────────────│                  │
└─────────────────┘                    └─────────────────┘
        │                                       │
        │                               notification
        │                                       ▼
        │                              ┌─────────────────┐
        │                              │  Notification   │
        │                              │   Handler       │
        │                              │   (userspace)   │
        │                              └─────────────────┘
        │                                       │
        │                              needs to make syscalls
        │                              (HTTP, file I/O, etc.)
        │                                       │
        │                              ┌─────────────────┐
        │                              │   seccomp        │
        │                              │   (BLOCKS!)      │
        └──────────────────────────────└─────────────────┘
```

**The deadlock cycle:**
1. Application makes syscall
2. seccomp intercepts, blocks application
3. Notification handler receives event
4. Handler needs to make syscall (HTTP to daemon for policy)
5. That syscall is also trapped by seccomp
6. Deadlock: handler waits for its own syscall, application waits for handler

### What We Tried

1. **Auto-allow all parent syscalls** - Helped, but child syscalls still blocked
2. **Auto-allow process syscalls (fork/exec)** - Helped shell start, but network syscalls still blocked
3. **Non-blocking try_recv** - Helped, but decision making still needs I/O
4. **spawn_blocking for async** - Helped PTY mode, but monitoring was lost

Each fix addressed a symptom, but the fundamental architecture remains broken.

### The Realization

**seccomp-unotify is designed for simple, synchronous allow/deny decisions.** It assumes:
- Policy is simple (syscall number + arguments)
- Decision is fast (no I/O required)
- Handler responds within milliseconds

When policy evaluation requires network calls, file I/O, or complex computation, seccomp-unotify breaks.

## eBPF Architecture

### Why eBPF is Different

**Asynchronous by design:**

```
┌─────────────────┐     syscall      ┌─────────────────┐
│   Application   │ ──────────────────│   Kernel         │
│   (traced)      │                    │   eBPF program   │
│                 │     continue       │   (fast filter)  │
│                 │ ◄─────────────────│                  │
└─────────────────┘                    └─────────────────┘
                                               │
                                               │ event (async)
                                               ▼
                                      ┌─────────────────┐
                                      │   Ring Buffer   │
                                      │   (perf buffer) │
                                      └─────────────────┘
                                               │
                                               │ read (async)
                                               ▼
                                      ┌─────────────────┐
                                      │   Userspace     │
                                      │   Daemon         │
                                      │   (no blocking)  │
                                      └─────────────────┘
```

**Key differences:**
1. eBPF program runs in kernel, can make immediate allow/deny decisions
2. Events are sent to userspace asynchronously via ring buffers
3. No blocking: kernel doesn't wait for userspace
4. Complex policy evaluation happens in userspace without affecting application

### Architecture Components

#### 1. eBPF Programs

```c
// syscall_intercept.bpf.c
SEC("tracepoint/syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 syscall_nr = ctx->id;

    // Fast path: check allowlist in eBPF map
    if (is_syscall_allowed(syscall_nr)) {
        return 0;  // Allow, no event sent
    }

    // Send event to userspace for policy evaluation
    struct event_t evt = {
        .pid = pid,
        .syscall = syscall_nr,
        .timestamp = bpf_ktime_get_ns(),
    };
    bpf_ringbuf_output(&events, &evt, sizeof(evt), 0);
    return 0;
}
```

#### 2. Network Interception

```c
// network_intercept.bpf.c
SEC("cgroup/sockops")
int sock_ops(struct bpf_sock_ops *skops) {
    switch (skops->op) {
    case BPF_SOCK_OPS_CONNECT:
    case BPF_SOCK_OPS_CONNECT6:
        // Capture connect() calls
        send_network_event(skops);
        break;
    }
    return 0;
}

SEC("cgroup_skb/egress")
int skb_egress(struct __sk_buff *skb) {
    // Capture outgoing packets
    return process_packet(skb);
}
```

#### 3. Userspace Daemon

```rust
// sevorix-daemon/src/main.rs
fn main() {
    // Load eBPF programs
    let bpf = Bpf::load(include_bytes_aligned!("syscall_intercept.bpf.o"))?;

    // Attach to tracepoints
    let tracepoint: Tracepoint = bpf.program_mut("sys_enter")?.try_into()?;
    tracepoint.attach("syscalls", "sys_enter")?;

    // Attach to cgroup for network interception
    let cgroup: SockOps = bpf.program_mut("sock_ops")?.try_into()?;
    cgroup.attach_cgroup("/sys/fs/cgroup/sevorix.slice")?;

    // Process events asynchronously
    let ring_buffer = RingBuffer::new(&bpf.map("events")?)?;

    loop {
        ring_buffer.consume(|event| {
            let evt: Event = parse_event(event);

            // Evaluate policy (async, can make network calls)
            let decision = evaluate_policy(&evt).await;

            // Log decision
            log_event(&evt, &decision);

            // No blocking the kernel - decisions are informational
        })?;
    }
}
```

### Event Flow

```
Application                Kernel                  Userspace Daemon
    │                         │                           │
    │ syscall()               │                           │
    │ ─────────────────────────►                           │
    │                         │                           │
    │                 eBPF program                         │
    │                 checks local                         │
    │                 allow/deny map                       │
    │                         │                           │
    │                    (allowed?)                       │
    │                         │                           │
    │                    ┌────┴────┐                      │
    │                    │         │                      │
    │                 allowed   blocked                  │
    │                    │         │                      │
    │                (continue)  (return error)          │
    │                    │                                │
    │                    │  event to ring buffer ─────────►│
    │                    │                                │
    │                    │                        async policy
    │                    │                        evaluation
    │                    │                        (HTTP, DB, etc.)
    │                    │                                │
    │ ◄────────────────────                               │
    │ (syscall returns)                                   │
```

### Policy Architecture

**Key principle: Four independent layers, no translation needed.**

Each layer intercepts at its natural level and evaluates independently:

```
User types: curl https://google.com
     │
     ▼
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 1: Shell (sevsh)                                             │
│  ─────────────────────────────                                      │
│  Intercepts: Command string BEFORE bash execution                   │
│  Sees: "curl https://google.com"                                    │
│  Policy example: Is "curl" in command allowlist?                    │
│  Decision: Allow → pass to bash, Deny → reject immediately         │
└─────────────────────────────────────────────────────────────────────┘
     │ (if allowed, bash executes curl)
     ▼
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 2: HTTP Proxy                                                │
│  ─────────────────────────────                                      │
│  Intercepts: HTTP requests via proxy environment                    │
│  Sees: GET https://google.com/                                      │
│        Headers, body, status code                                   │
│  Policy example: Is URL in allowlist? Method allowed?               │
│  Decision: Allow → forward request, Deny → return error            │
│  Note: Works for HTTPS via MITM certificate                         │
└─────────────────────────────────────────────────────────────────────┘
     │ (if allowed, proxy forwards request)
     ▼
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 3: Network (eBPF cgroup/sockops)                            │
│  ─────────────────────────────────────────                          │
│  Intercepts: connect() syscall arguments                            │
│  Sees: connect(fd, 142.250.80.46:443)                              │
│  Enrichment: Reverse DNS lookup → "google.com:443" (for display)   │
│  Policy example: Is destination IP:port in allowlist?               │
│  Decision: Allow → proceed, Deny → return EPERM                    │
│  Note: Catches ALL network traffic, not just HTTP                   │
└─────────────────────────────────────────────────────────────────────┘
     │ (if allowed, connection proceeds)
     ▼
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 4: Syscall (eBPF tracepoints)                               │
│  ─────────────────────────────────────                              │
│  Intercepts: All syscalls (execve, socket, connect, etc.)           │
│  Sees: Syscall number + arguments                                   │
│  Policy example: Is syscall in denylist?                           │
│  Decision: Allow → proceed, Deny → return error, Kill → SIGKILL    │
│  Note: Safety net for all kernel interactions                       │
└─────────────────────────────────────────────────────────────────────┘
```

#### Policy Format 1: Shell Commands

```yaml
# ~/.sevorix/policies/shell.yaml
policies:
  - name: allow-curl
    command: "curl"
    action: allow

  - name: deny-rm-recursive
    command: "rm"
    args: ["-rf", "/"]
    action: deny
```

**Evaluated by:** sevsh (userspace, before bash execution)
**No translation needed** - direct string matching on command input

#### Policy Format 2: HTTP Requests

```yaml
# ~/.sevorix/policies/http.yaml
policies:
  - name: allow-internal-api
    url_pattern: "https://api.internal.company.com/*"
    methods: [GET, POST]
    action: allow

  - name: deny-external-upload
    url_pattern: "https://*"
    methods: [POST, PUT]
    action: deny

  - name: audit-sensitive-endpoints
    url_pattern: "https://sensitive.company.com/*"
    action: audit
```

**Evaluated by:** HTTP proxy (userspace)
**Sees full HTTP semantics:** Method, URL, headers, body
**Works for HTTPS:** Via MITM certificate injection

#### Policy Format 3: Network Connections

```yaml
# ~/.sevorix/policies/network.yaml
policies:
  - name: allow-internal-api
    destination: "api.internal.company.com"
    ports: [443]
    action: allow

  - name: deny-databases
    ports: [3306, 5432, 27017]
    action: deny
```

**Evaluated by:** eBPF cgroup/sockops at connect() time
**Enrichment (display only):** IP → DNS reverse lookup for logging
**Catches all protocols:** TCP, UDP, DNS, etc. (not just HTTP)

#### Policy Format 4: Direct Syscalls

```yaml
# ~/.sevorix/policies/syscall.yaml
policies:
  - name: deny-kernel-module-load
    syscalls: ["init_module", "finit_module"]
    action: deny

  - name: restrict-privilege-escalation
    syscalls: ["setuid", "setgid", "capset"]
    action: audit
```

**Evaluated by:** eBPF tracepoints
**No translation needed** - direct syscall number matching

#### Layer Responsibilities

| Layer | Intercepts | Policy Format | Decision Point |
|-------|-----------|---------------|----------------|
| Shell | Command string | `command: "curl"` | Before bash |
| HTTP | HTTP requests | `url_pattern: "https://..."` | At proxy |
| Network | connect() args | `destination: "google.com"` | At connect time |
| Syscall | All syscalls | `syscalls: ["execve"]` | In kernel |

**Key insight: Layers are additive, not translations.**

- Shell layer catches intent at the highest level
- HTTP layer catches web requests with full semantics
- Network layer catches ALL connections (not just HTTP)
- Syscall layer is the safety net for everything else

A "curl" policy at shell level doesn't need to know about HTTP or connect() syscalls.
An HTTP policy about "google.com" doesn't need to know about shell commands or network IPs.
A network policy about IP:port doesn't need to know about HTTP semantics.
They're independent - evaluate what you see at each layer.

#### Shell Layer (sevsh)

**Current implementation (working before PTY):**

```rust
// sevsh evaluates the command BEFORE passing to bash
async fn validate_command(cmd: &str) -> Result<Verdict, Box<dyn std::error::Error>> {
    let client = Client::new();
    let url = "http://localhost:3000/analyze";

    // Query watchtower daemon for policy decision
    let resp = client
        .post(url)
        .json(&json!({
            "payload": cmd,
            "agent": "sevsh-repl",
            "context": "Shell"
        }))
        .send()
        .await;

    match resp {
        Ok(r) => {
            let json_resp: serde_json::Value = r.json().await?;
            let status = json_resp["status"].as_str().unwrap_or("UNKNOWN");
            let reason = json_resp["reason"].as_str().unwrap_or("Policy Violation");

            // ALLOW or FLAG = execute, BLOCK = deny
            let allowed = status == "ALLOW" || status == "FLAG";
            Ok(Verdict { allowed, status, reason })
        }
        Err(_) => {
            // Fail closed: if watchtower unreachable, block
            Ok(Verdict { allowed: false, status: "UNREACHABLE", reason: "Watchtower unreachable" })
        }
    }
}

// Interactive REPL loop
async fn run_interactive_repl(use_proxy: bool, trace: bool) -> Result<(), Box<dyn std::error::Error>> {
    let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
    let mut rl = DefaultEditor::new()?;

    loop {
        let readline = rl.readline("sevsh> ");
        match readline {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() { continue; }

                // 1. VALIDATE: Query watchtower before execution
                match validate_command(line).await {
                    Ok(verdict) => {
                        if verdict.allowed {
                            // 2. SET PROXY ENV VARS (for HTTP layer)
                            let env_vars: Vec<(String, String)> = if use_proxy {
                                vec![
                                    ("HTTP_PROXY", "http://localhost:3000"),
                                    ("HTTPS_PROXY", "http://localhost:3000"),
                                    // ... more proxy vars
                                ]
                            } else { vec![] };

                            // 3. EXECUTE: Pass to bash
                            let cmd_args = vec!["-c", line];
                            let mut command = Command::new(&shell);
                            command.args(&cmd_args);
                            for (key, value) in env_vars {
                                command.env(key, value);
                            }
                            command.status()?;
                        } else {
                            eprintln!("SEVORIX BLOCKED: {}", verdict.reason);
                        }
                    }
                    Err(e) => eprintln!("SEVORIX ERROR: {}", e),
                }
            }
            Err(ReadlineError::Eof) => break,
            _ => continue,
        }
    }
    Ok(())
}
```

**Key implementation details:**
- Uses `rustyline` for readline-like interface with history
- Queries watchtower daemon via HTTP POST to `/analyze`
- Request body: `{"payload": "<command>", "agent": "sevsh-repl", "context": "Shell"}`
- Response: `{"status": "ALLOW|BLOCK|FLAG", "reason": "...", "confidence": "..."}`
- **Fail closed**: If watchtower unreachable, blocks execution
- Sets proxy environment variables for HTTP layer integration

**Sandbox Mode (Network Isolation):**
- Uses Linux `unshare` to create isolated network namespace
- Bridges proxy traffic via Unix socket to host daemon
- Port forwarding support (`-p HOST:CONTAINER`)
- Fallback to env-var-only mode if `unshare`/`ip` unavailable

#### HTTP Layer (Proxy)

**Current implementation (working in proxy.rs):**

```rust
// proxy.rs - HTTP proxy evaluates full request semantics
pub async fn proxy_handler(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();

    // CONNECT method: Establish HTTPS tunnel
    if method == Method::CONNECT {
        if let Some(host) = uri.host() {
            let port = uri.port_u16().unwrap_or(443);
            let addr = format!("{}:{}", host, port);

            // Broadcast CONNECT event
            let event = json!({
                "verdict": "ALLOW",
                "lane": "GREEN",
                "payload": format!("CONNECT tunnel to {}", addr),
                "timestamp": chrono::Local::now().to_rfc3339(),
                "reason": "HTTPS Tunnel Established"
            });
            log_traffic_event(&state.traffic_log_path, &event.to_string());

            // Spawn tunnel task
            tokio::spawn(async move {
                let on_upgrade = hyper::upgrade::on(req);
                if let Ok(upgraded) = on_upgrade.await {
                    tunnel(upgraded, addr).await;
                }
            });

            return Response::new(Body::new(NoHintBody)); // 200 OK
        }
    }

    // HTTP request: Capture body for analysis
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await?;
    let body_str = String::from_utf8_lossy(&bytes).to_string();

    // 1. SECURITY SCAN: Poison pill detection
    let pill = PoisonPill::default_canary();
    if body_str.contains(pill.value) {
        return (StatusCode::FORBIDDEN, "SEVORIX CRITICAL: Honey-Pot Triggered");
    }

    // 2. POLICY CHECK: Scan content against policy engine
    let scan = scan_content(&body_str, Some("default"), &state.policy_engine, PolicyContext::Network);

    if scan.verdict == "BLOCK" {
        // Broadcast block event
        let event = json!({
            "verdict": "BLOCK",
            "lane": "YELLOW-BLOCK",
            "payload": format!("{} {}\n\n{}", method, uri, body_str),
            "timestamp": chrono::Local::now().to_rfc3339(),
            "reason": scan.log_msg
        });
        log_traffic_event(&state.traffic_log_path, &event.to_string());

        return (StatusCode::FORBIDDEN, format!("Request Blocked: {}", scan.log_msg));
    }

    // 3. FORWARD: Proxy request to destination
    let client = reqwest::Client::new();
    let mut req_builder = client.request(method, uri.to_string());
    for (key, value) in parts.headers.iter() {
        req_builder = req_builder.header(key, value);
    }
    req_builder = req_builder.body(bytes);

    let res = req_builder.send().await?;
    let body = Body::from_stream(res.bytes_stream());
    Response::new(body).with_status(res.status())
}
```

**What the proxy sees (JSON event logged):**

```json
{
  "verdict": "ALLOW",
  "lane": "GREEN",
  "payload": "POST https://api.example.com/data\n\n{\"user\": \"alice\"}",
  "timestamp": "2026-03-06T19:30:00Z",
  "latency": 45,
  "reason": "Request allowed",
  "confidence": "High",
  "context": "Network"
}
```

**Key implementation details:**
- Built on Axum (Rust web framework)
- Handles CONNECT method for HTTPS tunneling (MITM capability)
- Captures full request body for policy evaluation
- Integrates with policy engine via `scan_content()`
- Poison pill detection for honey-token security
- Broadcasts events to dashboard via channel
- Logs to `traffic_events.jsonl` for audit trail

#### Network Layer (eBPF)

```c
// eBPF evaluates connect() arguments, enriches for display
SEC("cgroup/sockops")
int sock_ops(struct bpf_sock_ops *skops) {
    if (skops->op == BPF_SOCK_OPS_CONNECT) {
        u32 ip = skops->remote_ip4;
        u16 port = skops->remote_port;

        // Check network policies (IP:port)
        if (is_network_allowed(ip, port)) {
            return 1;  // Allow
        }

        // Send event to userspace for logging/enrichment
        send_network_event(ip, port);
        return 0;  // Deny with EPERM
    }
    return 1;
}
```

**Enrichment (userspace, for display only):**

```rust
// Userspace daemon enriches network events with DNS
async fn handle_network_event(ip: u32, port: u16) {
    // Reverse DNS lookup for human-readable display
    let hostname = reverse_dns_lookup(ip).await.unwrap_or(ip.to_string());

    log_network_event(format!("{}:{}", hostname, port));
}
```

#### Syscall Layer (eBPF)

```c
// eBPF evaluates syscall numbers directly
SEC("tracepoint/syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 syscall_nr = ctx->id;

    // Check syscall policies
    if (is_syscall_denied(syscall_nr)) {
        // Return error or kill process
        return -EPERM;
    }

    // Send event to userspace for logging
    send_syscall_event(syscall_nr, ctx->args);
    return 0;  // Allow
}
```

## Implementation Plan

### Phase 1: Core eBPF Infrastructure (Week 1)

1. **eBPF program skeleton**
   - syscall tracepoint attachment
   - ring buffer for events
   - basic allow/deny map

2. **Userspace daemon**
   - Aya (Rust eBPF library) integration
   - Ring buffer consumer
   - Event parsing

3. **Build system**
   - eBPF compilation (cargo-bpf)
   - Integration with existing Sevorix build

### Phase 2: Syscall Interception (Week 2)

1. **Fast path filter**
   - Syscall number allowlist
   - Per-process tracking
   - Immediate allow/deny in kernel

2. **Slow path daemon**
   - HTTP communication with watchtower
   - Policy caching
   - Async decision making

3. **Enforcement via eBPF**
   - eBPF programs can return errors to deny syscalls
   - Can send signals (SIGKILL) to terminate processes
   - No separate seccomp layer needed

### Phase 3: Network Interception (Week 3)

1. **cgroup/sockops**
   - connect() interception
   - sendto/recvfrom tracking
   - Replaces HTTP proxy (works for all protocols, not just HTTP)

2. **cgroup_skb**
   - Packet capture
   - Connection-level visibility

3. **Integration with watchtower**
   - Network event enrichment
   - Destination IP/port logging

### Phase 4: Shell Command Interception (Week 4)

1. **Command parsing**
   - Parse execve arguments
   - Shell command reconstruction

2. **Policy evaluation**
   - Command allowlist/denylist
   - Argument validation

3. **Integration**
   - Non-interactive mode (`sevorix exec`)
   - Interactive mode with monitoring

## Comparison: seccomp vs eBPF

| Aspect | seccomp-unotify | eBPF |
|--------|-----------------|------|
| **Decision timing** | Must respond synchronously | Async, no kernel blocking |
| **I/O in handler** | ❌ Causes deadlocks | ✅ No blocking |
| **Network interception** | ❌ Not supported | ✅ sockops, cgroup_skb |
| **Policy complexity** | Simple only | Arbitrary complexity |
| **Performance** | High overhead per syscall | Low overhead (in-kernel filtering) |
| **Portability** | Good (Linux 3.5+) | Requires kernel 4.18+ |
| **Privileges required** | None | CAP_BPF or root |
| **Debugging** | Difficult (kernel/user boundary) | Better (userspace logs) |

## What We're Removing

### seccomp Layer

**Removing entirely.** eBPF provides both monitoring AND enforcement:
- eBPF can return errors to deny syscalls
- eBPF can send signals to kill processes
- One technology instead of two means less complexity

## What We're Keeping

### HTTP Proxy

**Keeping.** The proxy provides HTTP-level semantics that eBPF cannot:

**What eBPF CAN'T do:**
- See inside HTTPS traffic (encrypted)
- Parse HTTP methods/URLs/headers (requires userspace parsing)
- Provide rich JSON objects describing requests

**What the proxy DOES:**
- Captures full HTTP semantics (method, URL, headers, body)
- Works for HTTPS via MITM certificate
- Provides JSON objects for policy evaluation
- Allows policies like "deny POST to external URLs"

**Why we need BOTH proxy AND eBPF network:**

| Feature | HTTP Proxy | eBPF Network |
|---------|-----------|--------------|
| HTTP semantics | ✅ Full visibility | ❌ Encrypted |
| HTTPS body | ✅ Via MITM | ❌ Ciphertext |
| Non-HTTP protocols | ❌ HTTP only | ✅ TCP/UDP/DNS |
| No env vars needed | ❌ Requires proxy settings | ✅ Transparent |
| Request modification | ✅ MITM possible | ❌ Read-only |

They're complementary, not redundant.

## Recommendations

### Immediate Actions

1. **Pivot to eBPF** - The seccomp architecture cannot support the requirements
2. **Remove seccomp layer entirely** - eBPF handles both monitoring and enforcement
3. **Keep HTTP proxy** - Provides HTTP semantics eBPF cannot see
4. **Start with non-interactive mode** - Simpler to reason about, easier to test
5. **Use Aya for eBPF in Rust** - Well-maintained Rust eBPF library

### Technology Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                      Sevorix Watchtower                         │
│                    (Policy Decision Engine)                     │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ HTTP API
                              │
┌─────────────────────────────────────────────────────────────────┐
│                      Sevorix Daemon                             │
│                  (Userspace Event Processor)                    │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐       │
│  │ Ring Buffer   │  │ Policy Cache  │  │ Watchtower    │       │
│  │ Consumer      │  │ (HashMap)     │  │ Client        │       │
│  └───────────────┘  └───────────────┘  └───────────────┘       │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ ring buffer (async)
                              │
┌─────────────────────────────────────────────────────────────────┐
│                      Kernel eBPF Programs                       │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐       │
│  │ tracepoint/   │  │ cgroup/sockops│  │ cgroup_skb/   │       │
│  │ sys_enter     │  │ connect()     │  │ packets       │       │
│  └───────────────┘  └───────────────┘  └───────────────┘       │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐       │
│  │ Allowlist Map │  │ Denylist Map  │  │ Event Ring Buf│       │
│  └───────────────┘  └───────────────┘  └───────────────┘       │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ syscall / network
                              │
┌─────────────────────────────────────────────────────────────────┐
│                      Application                                │
│                  (sevsh / sevorix exec)                         │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  HTTP Proxy (userspace)                                  │   │
│  │  - Intercepts HTTP/HTTPS via env vars                   │   │
│  │  - Full request/response visibility                     │   │
│  │  - MITM for HTTPS                                       │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

**Four independent layers:**
1. **Shell (sevsh)** - Command string evaluation before bash
2. **HTTP Proxy** - Full HTTP semantics (method, URL, headers, body)
3. **Network eBPF** - All network connections (TCP/UDP/DNS, not just HTTP)
4. **Syscall eBPF** - All kernel interactions, enforcement capability

## Conclusion

The seccomp-unotify approach cannot achieve the goal of comprehensive syscall/network/command interception with policy evaluation. The synchronous notification model fundamentally conflicts with async I/O requirements.

**eBPF is the correct architecture** because:
1. It separates event capture from policy evaluation
2. The kernel doesn't block waiting for decisions
3. Complex policy evaluation can use network calls
4. It supports both syscall and network interception
5. Performance is better (in-kernel filtering)

**Four independent layers:**

| Layer | Technology | What it sees | Policy format |
|-------|------------|--------------|---------------|
| Shell | sevsh (userspace) | Command string | `command: "curl"` |
| HTTP | Proxy (userspace) | HTTP method/URL/headers/body | `url_pattern: "https://..."` |
| Network | eBPF cgroup | IP:port tuples | `destination: "google.com"` |
| Syscall | eBPF tracepoint | Syscall numbers | `syscalls: ["execve"]` |

**What we're removing:**
- **seccomp layer** - eBPF handles enforcement too

**What we're keeping:**
- **HTTP proxy** - Provides HTTP semantics eBPF cannot see (encrypted HTTPS, HTTP parsing)

**Next steps:**
1. Create `sevorix-ebpf` crate with basic syscall interception
2. Build userspace daemon with ring buffer consumer
3. Integrate with existing Sevorix Watchtower for policy decisions
4. Add network interception via cgroup programs
5. Restore HTTP proxy for HTTP-level policy evaluation
6. Implement `sevorix exec` command for testing

---

**References:**
- [Aya eBPF Library](https://github.com/aya-rs/aya)
- [Linux eBPF Documentation](https://www.kernel.org/doc/html/latest/bpf/index.html)
- [Seccomp Unotify Limitations](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)