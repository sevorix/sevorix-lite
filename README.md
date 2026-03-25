# 🛡️ Sevorix Watchtower (Lite)

> **Runtime Containment for Autonomous AI Agents.**
> *Zero-Latency. Action-Centric. Rust-Native.*

![Build Status](https://img.shields.io/badge/build-passing-brightgreen) ![Rust](https://img.shields.io/badge/built%20with-Rust-orange) ![License](https://img.shields.io/badge/license-AGPL--3.0-blue)

Most developers think an "AI Gateway" is enough. But if your agent gets a raw shell command or a direct network socket, it bypasses the gateway entirely. Sevorix Lite is an open-source, local runtime firewall that enforces an inescapable **Action Authorization Boundary** on your AI agents. 

It intercepts, records, and blocks dangerous/undesirable activity in < 20ms. What is considered dangerous and undesirable is completely up to you!

---

## ⚡ Quick Start (Under 60 Seconds)

### 1. Prerequisites
Requires Linux/WSL/macOS and Rust (`cargo`).
*Don't have Rust installed? Get it in one line:*
`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

### 2. Install
```bash
git clone [https://github.com/sevorix/sevorix-lite.git](https://github.com/sevorix/sevorix-lite.git)
cd sevorix-lite
./install.sh
```

### 3. Start the Daemon
Launch the Sevorix Control Plane in the background.
```bash
sevorix start
sevorix status
```

### 4. Open the Watchtower Dashboard
Navigate to your local command center to see real-time enforcement:
👉 **`http://localhost:3000/dashboard/desktop.html`**

---

## 🏎️ The Test Drive: See it in Action

Don't trust us. Test it. We've included `sevsh`, a secure shell wrapper that routes commands through the Sevorix engine before they ever hit the processor. 

Leave your Dashboard open in a browser, and run these in your terminal:

### Scenario 1: The Green Lane (Allowed)
Run a benign command.
```bash
./sevsh -c "echo 'Agent is thinking...'"
```
**Result:** The command executes normally.

### Scenario 2: The Red Lane (Zero-Latency Kill Switch)
Simulate a rogue agent trying to drop a database table. Our default `policies.json` strictly forbids the `DROP` keyword.
```bash
./sevsh -c "DROP TABLE users;"
```
**Result:** The command is instantly vaporized. You will see `SEVORIX BLOCKED: Policy Violation` in your terminal.

### Scenario 3: The Yellow Lane (Human-in-the-Loop)
Simulate an agent trying to access sensitive data. Our default policy flags the `SELECT` keyword for human review.
```bash
./sevsh -c "SELECT * FROM admin_credentials;"
```
**Result:** The terminal hangs. Switch to your **Dashboard**. You will see a Yellow Intervention Panel with a countdown timer. Click **Block** or **Allow** to determine the outcome.

---

## 🤖 AI Agent Integrations (The Vault)

Sevorix isn't just for manual testing. We integrate directly with your favorite autonomous coding agents to put them in a secure sandbox. 

Currently supporting **Claude Code** (with Codex and OpenClaw in active development).

> See **[docs/INTEGRATIONS.md](docs/INTEGRATIONS.md)** for full usage, internals, and per-tool guides.

### Securing Claude Code
When you start Claude Code through Sevorix, we use a Linux mount namespace to bind-mount `sevsh` over `/bin/bash`. This means even if Claude uses an absolute path to try and bypass security, it hits our inescapable lock.

**1. Install the Integration:**
```bash
sevorix integrations install claude
```
*(Note: This just checks prerequisites; it does not modify your system config).*

**2. Launch Claude in the Vault:**
```bash
sevorix integrations start claude
```

**3. Pass Arguments seamlessly:**
```bash
sevorix integrations start claude -- /path/to/project --resume
```

Claude is now running. Any command it attempts to execute will be intercepted, evaluated against your policies, and governed by Sevorix. 

---

## ⚙️ How it Works: The Architecture

Sevorix Watchtower relies on physics, not suggestions. We enforce a **Three-Lane Traffic** system:

1.  **🔴 Red Lane (The Block):** Deterministic kills. SQL Injection, Data Exfiltration, Financial Theft. (Latency: ~0ms).
2.  **🟡 Yellow Lane (Intervention):** Ambiguous intent **held** for operator review. Request is suspended until Allow/Block decision or timeout.
3.  **🟢 Green Lane (The Pass):** Approved patterns passed with zero overhead.

### Customizing Permissions

Permissions are created using two constructs: roles and policies. A policy is a rule for blocking or flagging activity, and a role is a collection of policies. By default during installation you will have a default role and policy set installed. The defaults are **NOT** a comprehensive or particularly useful set of rules, but rather a tool for validating your install and starting point for creating real, effective rule sets.

#### Policy JSON Schema

```json
{
  "id": "unique-policy-id",
  "type": "Simple",
  "pattern": "DROP TABLE",
  "action": "Block",
  "context": "Shell",
  "kill": false
}
```

| Field     | Type    | Description |
|-----------|---------|-------------|
| `id`      | string  | Unique identifier (kebab-case recommended) |
| `type`    | enum    | `Simple`, `Regex`, or `Executable` |
| `pattern` | string  | The match pattern (see match types below) |
| `action`  | enum    | `Block`, `Flag`, or `Allow` |
| `context` | enum    | `Shell`, `Network`, `Syscall`, or `All` (default: `All`) |
| `kill`    | bool    | If true, kill the traced process instead of returning EPERM. Use only for critical violations. |

#### Match Types

- **`Simple`** — Substring match (case-sensitive). Fast and predictable.
  ```json
  { "type": "Simple", "pattern": "DROP TABLE" }
  ```

- **`Regex`** — Full Rust regex match. Compiled once and cached.
  ```json
  { "type": "Regex", "pattern": "(?i)(drop|delete|truncate)\\s+table" }
  ```

- **`Executable`** — Pipes the content to an external command via stdin; blocks if exit code is 0. Powerful but slow — use sparingly and only for complex logic that Simple/Regex can't express.
  ```json
  { "type": "Executable", "pattern": "grep -qi 'wire.*funds'" }
  ```
  > **Security warning**: Always review executable policies published on SevorixHub before pulling.

#### Actions

| Action  | Meaning |
|---------|---------|
| `Block` | Hard reject. |
| `Flag`  | Soft reject — marks the action for review and pauses execution. |
| `Allow` | Explicit permit — overrides nothing but documents intent. |
> Flag doesn't work well with Syscall yet, and will post a message to the user but block the syscall without an option for allowing.

#### Policy Context

Scope policies to specific interception layers:

| Context   | When it applies |
|-----------|-----------------|
| `Shell`   | Agent shell commands intercepted before execution |
| `Network` | Outbound HTTP requests through the proxy |
| `Syscall` | Low-level syscall interception (eBPF feature) |
| `All`     | All contexts (default) |

Use `context` to avoid false positives — e.g., a policy blocking `DELETE` should use `context: "Network"` if you only want to block HTTP DELETE methods, not shell `delete` commands.

#### Role Schema

Roles group policies and are assigned to agents:

```json
{
  "name": "restricted-agent",
  "policies": ["block-destructive-sql", "block-wire-funds", "flag-admin-ops"],
  "is_dynamic": false
}
```

An agent running with `restricted-agent` will only be evaluated against policies in that role.

#### File Locations

- **Policies**: `~/.sevorix/policies/` — each `.json` file is one policy or an array of policies
- **Roles**: `~/.sevorix/roles/` — each `.json` file is one role or an array of roles

Files are loaded automatically when the daemon starts. No restart needed if you use `sevorix validate` for testing.

---

## 🛠️ CLI Reference
Manage your local enforcement node with the unified `sevorix` CLI.

```bash
sevorix start               # Start daemon
sevorix stop                # Kill daemon
sevorix config check        # Validate your policies.json
sevorix validate "CMD"      # Test a command against rules
sevorix integrations list   # Show available AI sandboxes
```

---

## ⚠️ Common Installation Issues

**1. "command not found: sevorix" or "command not found: sevsh"**
* **The Fix:** Your system doesn't know where the installed binaries are. They are likely in `~/.local/bin`. Run this to add it to your path:
  `export PATH=$PATH:~/.local/bin`
  *(Tip: Add that line to your `~/.bashrc` or `~/.zshrc` file to make it permanent).*

**2. Port 3000 is already in use**
* **The Fix:** The Sevorix Watchtower dashboard runs on port 3000 by default. If you have a React or Node.js app running in the background, Sevorix might fail to start. Kill the process using port 3000, then run `sevorix start` again. Support for designating a port other than the default 3000 coming soon.

**3. Permission Denied during Claude Code Integration**
* **The Fix:** When you run `sevorix integrations start claude`, Sevorix uses a Linux mount namespace to safely lock the agent down. This requires temporary `sudo` privileges. Ensure your user has sudo rights, or check that the installer successfully placed the rule in `/etc/sudoers.d/sevorix-claude`.

---

**License:** Open source under the AGPL-3.0 license. For commercial or enterprise use, contact `chris@sevorix.com`.