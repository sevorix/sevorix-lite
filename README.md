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
2.  **🟡 Yellow Lane (Policy Analysis):** Ambiguous intent evaluated against your configured policy rules.
3.  **🟢 Green Lane (The Pass):** Approved patterns passed with zero overhead.

---

## 🚀 Key Features

### 1. 🍬 The "Poison Pill" (Honey-Pot)
We proactively integrity-test agents by injecting invisible "canary" credentials into their context window.
* **Mechanism:** Injects `AWS_SECRET = "sev-canary-999"`.
* **Detection:** If the agent attempts to *use* this key, Sevorix detects the breach in the output stream.
* **Action:** Instant TCP Sever.

### 2. ⚡ "Red Lane" Financial Limits
Hardcoded safety ceilings for autonomous transactions.
* **Current Policy:** Blocks any `WIRE_FUNDS` > $500.

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
