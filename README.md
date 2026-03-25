# 🛡️ Sevorix Lite

**Stop rogue AI before it destroys your system.**

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/sevorix/sevorix-lite)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
![Rust](https://img.shields.io/badge/built%20with-Rust-orange)

---

## 🚨 The Problem

You deployed Claude Code, AutoGPT, or a custom LLM agent. It's powerful. It's also dangerous.

**Without Sevorix, an agent can:**
- 🗑️ Delete your entire filesystem: `rm -rf /`
- 🔓 Steal credentials and API keys
- 💸 Execute unauthorized financial transactions
- 🚀 Launch attacks on other systems
- 📊 Exfiltrate sensitive data

**Sevorix Lite stops this.** It sits between your agent and the outside world, enforcing security policies in real-time with **zero-latency overhead**.

---

## ⚡ Quick Start (5 minutes)

### Step 1: Install

```bash
git clone https://github.com/sevorix/sevorix-lite.git
cd sevorix-lite
./install.sh
```

### Step 2: Start the Daemon

```bash
sevorix start
```

### Step 3: View the Dashboard

Open your browser to: **http://localhost:3000/dashboard**

✅ **That's it!** Sevorix is now running and protecting your system.

---

## 📋 Real-World Examples

### Example 1: Block Dangerous Commands

Your AI agent tries to execute `rm -rf /`. **Sevorix blocks it immediately.**

**Setup (one-time):**

```json
{
  "policies": [
    {
      "id": "block-rm-rf",
      "pattern": "rm -rf /",
      "action": "Block",
      "context": "Shell"
    }
  ]
}
```

**Result:**

```
Agent: "I'll delete the /tmp directory"
Agent executes: rm -rf /tmp/...
Sevorix: ❌ BLOCKED - Matches dangerous pattern
Agent gets: Command denied
System: ✅ Safe
```

---

### Example 2: Require Human Approval for Sensitive Actions

Your agent wants to modify the database. Before it happens, you approve it.

**Setup:**

```json
{
  "policies": [
    {
      "id": "alert-on-delete",
      "pattern": "DELETE FROM users",
      "action": "Intervention",
      "context": "Network"
    }
  ]
}
```

**Result:**

1. Agent tries to run: `DELETE FROM users WHERE id=1`
2. Sevorix **pauses the query**
3. Your dashboard shows: "⚠️ Pending Decision Required"
4. You click **Allow** or **Block** within 60 seconds
5. Query executes (or is rejected) based on your decision

---

### Example 3: Log All Network Requests

Monitor what your agent is doing without blocking anything (useful for testing):

**Setup:**

```json
{
  "policies": [
    {
      "id": "audit-all-network",
      "action": "Allow",
      "context": "Network",
      "log": true
    }
  ]
}
```

**Result:**

Your dashboard shows every HTTP/HTTPS request the agent makes.

---

## 🎯 Who Should Use This?

- 🤖 **AI Agent Developers**: Building with Claude, LangChain, AutoGPT, Anthropic API
- 🔬 **AI Researchers**: Running autonomous systems in production
- 🛡️ **DevOps/Security Teams**: Deploying LLM applications securely
- 💼 **Enterprise Companies**: Need compliance + security for AI workloads

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| **🔴 Red Lane** | Instant blocking of dangerous patterns (~0ms latency) |
| **🟡 Yellow Lane** | Pause suspicious actions for human review |
| **🟢 Green Lane** | Allow approved patterns with zero overhead |
| **📊 Dashboard** | Real-time monitoring and policy management |
| **⚡ Low Latency** | <20ms overhead on agent commands |
| **🔌 Integrations** | Works with Claude Code, LangChain, custom agents |

---

## 📖 How It Works

### The Three Lanes

1. **🔴 Red Lane (Instant Block)**
   - Pattern matches a dangerous rule → Blocked immediately
   - Latency: ~0ms

2. **🟡 Yellow Lane (Human Review)**
   - Pattern is ambiguous → Request is held
   - Dashboard alerts you → You decide Allow/Block

3. **🟢 Green Lane (Pass Through)**
   - Pattern matches an approved rule → Passes through
   - Latency: ~0ms

---

## 🛠️ Installation Options

### Option A: Build from Source (Recommended)

```bash
git clone https://github.com/sevorix/sevorix-lite.git
cd sevorix-lite
./install.sh
```

### Option B: Download Pre-Built Binary

Visit [Releases](https://github.com/sevorix/sevorix-lite/releases) and download the binary for your OS.

---

## 📚 Configuration

### Basic Setup: ~/.sevorix/config.json

```json
{
  "policies": [
    {
      "id": "block-rm-rf",
      "pattern": "rm -rf /",
      "action": "Block",
      "context": "Shell"
    }
  ],
  "intervention": {
    "timeout_secs": 60,
    "timeout_action": "block"
  }
}
```

---

## 🚀 Next Steps

1. **Configure your policies** → Edit `~/.sevorix/config.json`
2. **Test with your agent** → Run Claude Code or LangChain
3. **Monitor the dashboard** → Watch policies in action

---

## 📄 License

Sevorix Lite is open source under the **[AGPL-3.0](LICENSE)** license.

For commercial use, contact: **chris@sevorix.com**

---

## 💬

