# 🛡️ Sevorix Watchtower (Lite)

> **Runtime Containment for Autonomous AI Agents.**
> *Zero-Latency. Action-Centric. Rust-Native.*

![Build Status](https://img.shields.io/badge/build-passing-brightgreen) ![Rust](https://img.shields.io/badge/built%20with-Rust-orange) ![License](https://img.shields.io/badge/license-Apache--2.0-blue)

---

## 🏗️ The Architecture
Sevorix Watchtower is a **sidecar proxy** designed to solve the "Logic Gap" in AI Agent security. Unlike traditional WAFs (Identity) or Prompt Filters (Input), Sevorix verifies **Intent & Execution** in real-time.

It sits on the wire between your Agent and the World, enforcing a **<20ms latency budget**.

### The Traffic Lanes
1.  **🔴 Red Lane (The Block):** Deterministic kills. SQL Injection, Data Exfiltration, Financial Theft. (Latency: ~0ms).
2.  **🟡 Yellow Lane (Intervention):** Ambiguous intent **held** for operator review. Request is suspended until Allow/Block decision or timeout.
3.  **🟢 Green Lane (The Pass):** Approved patterns passed with zero overhead.

---

## 🚀 Key Features

### 1. ⚡ Red Lane: Policy-Based Blocking

The Red Lane provides **zero-latency, deterministic blocking** driven entirely by your configured policies. Any policy with `Action: Block` that matches a request sends it to the Red Lane — no LLM involved, ~0ms latency.

#### Traffic Channel Coverage

| Channel | Red Lane support |
|---------|-----------------|
| Network (HTTP proxy) | ✅ Request blocked before forwarding |
| Shell (via `sevsh`) | ✅ Command denied before execution |
| Syscall (eBPF tracepoints) | ✅ Syscall denied via `EPERM` (or process killed if `kill: true`) |

#### Policy Match Types

| Type | Description |
|------|-------------|
| `Simple` | Substring match |
| `Regex` | Full regular expression match |
| `Executable` | Pipes content to an external command; blocks if exit code is 0 |

Policies are scoped by **context** (`Shell`, `Network`, `Syscall`, `All`) and assigned to **roles**. If no role is configured for an agent, all traffic is blocked by default.

#### Example Policy

```json
{
  "id": "block-drop",
  "type": "Simple",
  "pattern": "DROP TABLE",
  "action": "Block",
  "context": "Shell",
  "kill": false
}
```

---

### 2. 🧑‍💼 Human-in-the-Loop Intervention

When a request is flagged as Yellow Lane, Watchtower **holds the request open** and routes it to a human operator for review.

#### How It Works

1. A flagged request arrives (Yellow Lane verdict).
2. Watchtower suspends the request and broadcasts a **PENDING** event over WebSocket.
3. The dashboard displays an **intervention panel** — a yellow overlay showing the payload, reason, and a countdown timer.
4. The operator clicks **Allow** or **Block** within the timeout window.
5. Watchtower completes or rejects the request based on the decision.
6. If no decision is made before the timeout, the configured default action fires (**block**, by default).

The operator can also **Pause** the countdown for longer review without committing to a decision.

#### Coverage

| Channel | Blocking support |
|---------|-----------------|
| Network (HTTP proxy) | ✅ Full hold-and-wait |
| Shell (via `sevsh`) | ✅ Full hold-and-wait |
| Syscall (eBPF tracepoints) | 🔔 Dashboard notification only |

#### Configuration (`~/.sevorix/settings.json`)

```json
{
  "intervention": {
    "timeout_secs": 30,
    "timeout_action": "block"
  }
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `timeout_secs` | `30` | Seconds to wait for an operator decision before auto-acting. |
| `timeout_action` | `"block"` | Action on timeout: `"block"` or `"allow"`. |

#### API Endpoints

| Endpoint | Method | Body | Description |
|----------|--------|------|-------------|
| `/api/decide` | POST | `{ "event_id": "...", "action": "allow"\|"block" }` | Submit an operator decision. |
| `/api/pause` | POST | `{ "event_id": "...", "paused": true\|false }` | Freeze or resume the countdown. |

---

## 🛡️ Tooling Ecosystem

### 1. Unified CLI (`sevorix`)
**The Control Plane.**

The Rust binary includes a built-in daemon manager for seamless background execution.

```bash
# Start the Watchtower server (Daemon mode)
sevorix start
# Logs: ~/.local/state/sevorix/sevorix.log

# Check status
sevorix status

# Stop the daemon
sevorix stop

# Run in foreground (for debugging)
sevorix run

# Check configuration
sevorix config check
```

### 2. SevShell (`sevsh`)
**The Secure Shell Wrapper.**

`sevsh` is a Rust binary that wraps your shell execution (e.g., `/bin/bash`). Before executing *any* command, it sends the proposed command to Sevorix Watchtower for analysis.

*   **Verdict = ALLOW:** Command executes normally.
*   **Verdict = BLOCK:** Execution is denied, process exits.

**Usage:**

```bash
./sevsh -c "rm -rf /"
```

---

## 🛠️ Quick Start

### Prerequisites
*   **Linux/WSL/macOS**
*   **Rust (`cargo`)** (Optional, for building from source)

### Installation

**Option A: Install from Source**
```bash
git clone https://github.com/sevorix/sevorix-lite.git
cd sevorix-lite
./install.sh
```

**Option B: Install from Binary Distribution**
Download and unzip the release, then run:
```bash
cd sevorix-release
./install.sh
```

### Usage

1.  **Start the Daemon:**
    ```bash
    sevorix start
    ```
2.  **View Dashboard:**
    Open `http://localhost:3000/dashboard/desktop.html`
