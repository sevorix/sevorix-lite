# Sevorix Integrations

Integrations connect Sevorix Watchtower to specific AI coding tools so their
shell commands are validated before execution. Each integration is managed via
the `sevorix integrations` CLI.

---

## CLI Reference

```
sevorix integrations list
sevorix integrations status [name]
sevorix integrations install <name>
sevorix integrations uninstall <name>
sevorix integrations start <name> [-- tool-args...]
```

**Name aliases** — the following are all equivalent:

| Canonical name | Accepted aliases      |
|----------------|-----------------------|
| `Claude Code`  | `claude`, `claude-code` |

---

## General Usage

### Check what's available

```sh
sevorix integrations list
```

### Verify an integration's prerequisites

```sh
sevorix integrations install claude
```

`install` doesn't write anything to disk for most integrations — it validates
that all required binaries are present and the Sevorix daemon is running. If
anything is missing it prints a clear error.

### Check status

```sh
sevorix integrations status claude
```

Returns one of:
- **Installed** — all prerequisites met, ready to start
- **NotInstalled** — binaries missing (re-run the installer)
- **Corrupted** — a specific prerequisite is broken (reason printed)

### Launch a monitored session

```sh
sevorix integrations start claude
```

Extra arguments are forwarded to the underlying tool:

```sh
sevorix integrations start claude -- --resume
sevorix integrations start claude -- /path/to/project
```

---

## How Interception Works

### The problem

AI coding agents like Claude Code call `/bin/bash` by **absolute path** when
running Bash tool commands. Techniques that manipulate `$SHELL` or `$PATH`
don't help here — the agent bypasses PATH lookup entirely.

### The solution: mount namespace bind-mount

`sevorix integrations start claude` execs `sudo sevorix-claude-launcher`,
which performs the following steps:

```
1. sudo sevorix-claude-launcher
       │
       ├── unshare --mount          # create a new mount namespace
       │                            # (scoped to this process tree only)
       │
       ├── mount --bind /bin/bash → $TMPFILE   # stash real bash somewhere safe
       │
       ├── mount --bind sevsh → /bin/bash      # replace bash inside the namespace
       │
       └── runuser -u $ORIGINAL_USER           # drop back to your user
               └── claude [args]               # launch Claude Code
```

Inside the session, `/bin/bash` **is** sevsh. Outside the session (every other
process on the machine), `/bin/bash` is still the real bash. The mount is torn
down automatically when the claude session exits.

### Recursion prevention

Without extra handling, sevsh would call `/bin/bash` to execute validated
commands, hit the bind-mount, and call itself forever. The launcher prevents
this by bind-mounting the real bash to a temporary file and passing its path
as `$SHELL` and `$SEVORIX_REAL_SHELL` before replacing `/bin/bash`. sevsh
uses `$SEVORIX_REAL_SHELL` for execution rather than `/bin/bash`.

### Why root is required

`mount --bind` over an existing system path requires `CAP_SYS_ADMIN`. The
launcher is installed to `/usr/local/bin/sevorix-claude-launcher` with a
passwordless sudoers rule so users don't have to type a password. The
privilege is shed immediately after the mounts are set up via `runuser`.

---

## Claude Code Integration

### Prerequisites

| Requirement | Path | Installed by |
|---|---|---|
| Sevorix daemon running | `~/.local/state/sevorix/sevorix.pid` | `sevorix start` |
| sevsh binary | `~/.local/bin/sevsh` | `./install.sh` |
| Launcher binary | `/usr/local/bin/sevorix-claude-launcher` | `./install.sh` |
| Sudoers rule | `/etc/sudoers.d/sevorix-claude` | `./install.sh` |

Run the installer to set everything up:

```sh
./install.sh
```

### Starting a session

```sh
sevorix start                        # ensure daemon is running
sevorix integrations start claude    # launch Claude Code under monitoring
```

All bash commands Claude runs will flow through sevsh and be evaluated against
your policies before execution.

### Passing arguments to Claude Code

Arguments after `--` are forwarded directly:

```sh
sevorix integrations start claude -- --resume
sevorix integrations start claude -- --model claude-opus-4-6
sevorix integrations start claude -- /path/to/project
```

### What gets intercepted

Once inside a monitored session, sevsh intercepts every command Claude
attempts to run via its Bash tool. Each command is:

1. Submitted to the Sevorix policy engine
2. Evaluated against your Red/Yellow/Green lane rules and policy files
3. Either executed (ALLOW), flagged for review (FLAG), or blocked (BLOCK)

Network requests are also intercepted by the proxy layer regardless of
whether the mount-namespace integration is active.

### Verifying interception is active

Inside a Claude Code session you can ask Claude to run:

```
which bash
echo $SEVORIX_REAL_SHELL
```

`which bash` should resolve to the real bash (since `which` itself resolves
after the bind-mount), but every command Claude runs via its Bash tool will go
through sevsh. The presence of `$SEVORIX_REAL_SHELL` in the environment
confirms the launcher is active.

To see live traffic, open the dashboard:

```
http://localhost:3000/dashboard/desktop.html
```

---

## Codex Integration

Codex CLI respects the `$SHELL` environment variable, so the integration
modifies `~/.codex/config.json` to set `SHELL` to sevsh directly — no mount
namespace needed.

```sh
sevorix integrations install codex
sevorix integrations status codex
sevorix integrations uninstall codex
```

---

## OpenClaw Integration

Similar to Codex — configures OpenClaw to use sevsh via its config file.

```sh
sevorix integrations install openclaw
sevorix integrations status openclaw
sevorix integrations uninstall openclaw
```

---

## Adding a New Integration

Implement the `Integration` trait from `src/integrations/mod.rs`:

```rust
pub trait Integration: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn is_installed(&self) -> bool;
    fn install(&self) -> Result<InstallResult>;
    fn uninstall(&self) -> Result<()>;
    fn status(&self) -> IntegrationStatus;
}
```

Then register it in `handle_integrations` in `src/lib.rs` and add a `start`
handler if the tool needs a launcher (see the `IntegrationsCommands::Start`
match arm for the Claude Code pattern).

If the target tool respects `$SHELL`, the simplest approach is to follow the
Codex pattern: modify the tool's config file to point `SHELL` at sevsh. If it
calls `/bin/bash` by absolute path, follow the Claude Code pattern and build
a launcher script that sets up a mount namespace.
