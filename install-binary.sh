#!/bin/bash
set -e

# Sevorix Binary Installer
# Run this from an extracted release bundle containing:
#   sevorix, sevsh, scripts/sevorix-cgroup-helper, scripts/sevorix-claude-launcher

INSTALL_DIR="$HOME/.local/bin"
CONFIG_DIR="$HOME/.sevorix"
STATE_DIR="$HOME/.local/state/sevorix"

# ---------------------------------------------------------------
# Parse flags
# ---------------------------------------------------------------
FORCE=0
for arg in "$@"; do
    case "$arg" in
        --force|-f) FORCE=1 ;;
        --help|-h)
            echo "Usage: ./install-binary.sh [--force]"
            echo ""
            echo "  --force  Skip all confirmation prompts (non-interactive install)"
            exit 0
            ;;
    esac
done

# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------

prompt_confirm() {
    local title="$1"
    local detail="$2"

    if [ "$FORCE" -eq 1 ]; then
        return 0
    fi

    echo ""
    echo "┌─ $title"
    echo "│  $detail"
    printf "└─ Proceed? [Y/n] "
    read -r answer
    case "$answer" in
        [nN][oO]|[nN])
            echo "   ↩ Skipped."
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

echo "--------------------------------------------------"
echo "🛡️  Sevorix Watchtower Binary Installer"
if [ "$FORCE" -eq 1 ]; then
    echo "   Running in --force mode (no prompts)"
fi
echo "--------------------------------------------------"

# ---------------------------------------------------------------
# Verify we're in a valid bundle
# ---------------------------------------------------------------
if [ ! -f "sevorix" ]; then
    echo "❌ 'sevorix' binary not found in current directory."
    echo "   Run this script from the extracted release bundle."
    exit 1
fi

if [ ! -f "sevsh" ]; then
    echo "⚠️  'sevsh' binary not found — shell interception will be unavailable."
fi

# ---------------------------------------------------------------
# Create user directories
# ---------------------------------------------------------------
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$CONFIG_DIR/bin"
mkdir -p "$CONFIG_DIR/policies"
mkdir -p "$CONFIG_DIR/roles"
mkdir -p "$STATE_DIR"

# Create bash wrapper so integrations can shadow bash via PATH
cat > "$CONFIG_DIR/bin/bash" << 'EOF'
#!/bin/sh
exec "$HOME/.local/bin/sevsh" "$@"
EOF
chmod +x "$CONFIG_DIR/bin/bash"

# ---------------------------------------------------------------
# Stop existing daemon before overwriting binaries
# ---------------------------------------------------------------
if [ -f "$INSTALL_DIR/sevorix" ]; then
    echo "🔄  Stopping any running Sevorix instances..."
    "$INSTALL_DIR/sevorix" stop 2>/dev/null || true
    sleep 1
fi

# ---------------------------------------------------------------
# Install binaries
# ---------------------------------------------------------------
echo "🚀 Installing sevorix to $INSTALL_DIR..."
cp "sevorix" "$INSTALL_DIR/sevorix"
chmod +x "$INSTALL_DIR/sevorix"

if [ -f "sevsh" ]; then
    echo "🚀 Installing sevsh to $INSTALL_DIR..."
    rm -f "$INSTALL_DIR/sevsh"
    cp "sevsh" "$INSTALL_DIR/sevsh"
    chmod +x "$INSTALL_DIR/sevsh"
else
    echo "ℹ️  sevsh not found — skipping."
fi

if [ -f "sevorix-ebpf-daemon" ]; then
    echo "🚀 Installing sevorix-ebpf-daemon to $INSTALL_DIR..."
    rm -f "$INSTALL_DIR/sevorix-ebpf-daemon"
    cp "sevorix-ebpf-daemon" "$INSTALL_DIR/sevorix-ebpf-daemon"
    chmod +x "$INSTALL_DIR/sevorix-ebpf-daemon"

    if prompt_confirm \
        "Grant eBPF Linux capabilities to sevorix-ebpf-daemon" \
        "Allows the daemon to load eBPF programs without running as root. Runs: sudo setcap cap_bpf,cap_perfmon,cap_net_admin,cap_sys_admin+ep $INSTALL_DIR/sevorix-ebpf-daemon"; then
        if sudo setcap cap_bpf,cap_perfmon,cap_net_admin,cap_sys_admin+ep "$INSTALL_DIR/sevorix-ebpf-daemon"; then
            echo "   ✅ Capabilities granted"
        else
            echo "   ⚠️  setcap failed — eBPF daemon may require sudo to run."
        fi
    else
        echo "   ⚠️  Capabilities not granted — eBPF daemon will require sudo to run."
    fi

    SUDOERS_FILE="/etc/sudoers.d/sevorix-ebpf"
    SUDOERS_RULE="$USER ALL=(root) NOPASSWD: $INSTALL_DIR/sevorix-ebpf-daemon"
    if prompt_confirm \
        "Install passwordless sudoers rule for eBPF daemon" \
        "Allows Sevorix to launch the eBPF daemon without a sudo password prompt.
│  Writes to: $SUDOERS_FILE
│  Rule: $SUDOERS_RULE"; then
        if echo "$SUDOERS_RULE" | sudo tee "$SUDOERS_FILE" > /dev/null && sudo chmod 440 "$SUDOERS_FILE"; then
            echo "   ✅ Sudoers rule installed at $SUDOERS_FILE"
        else
            echo "   ⚠️  Failed to install sudoers rule."
            echo "   Add manually via visudo: $SUDOERS_RULE"
        fi
    else
        echo "   ⚠️  Sudoers rule skipped. Add manually via visudo if needed:"
        echo "      $SUDOERS_RULE"
    fi
else
    echo "ℹ️  sevorix-ebpf-daemon not found — eBPF monitoring will be unavailable."
fi

# ---------------------------------------------------------------
# Install cgroup helper (per-session process isolation)
# ---------------------------------------------------------------
CGROUP_HELPER="/usr/local/bin/sevorix-cgroup-helper"
if [ -f "scripts/sevorix-cgroup-helper" ]; then
    if prompt_confirm \
        "Install cgroup helper to /usr/local/bin" \
        "System-wide helper for per-session process isolation. Requires sudo write to /usr/local/bin."; then
        if sudo cp "scripts/sevorix-cgroup-helper" "$CGROUP_HELPER" && sudo chmod 755 "$CGROUP_HELPER"; then
            echo "   ✅ Cgroup helper installed"
            CGROUP_SUDOERS_FILE="/etc/sudoers.d/sevorix-cgroup"
            CGROUP_SUDOERS_RULE="$USER ALL=(root) NOPASSWD: $CGROUP_HELPER"
            if prompt_confirm \
                "Install passwordless sudoers rule for cgroup helper" \
                "Allows Sevorix to manage process isolation without a sudo password prompt.
│  Writes to: $CGROUP_SUDOERS_FILE
│  Rule: $CGROUP_SUDOERS_RULE"; then
                if echo "$CGROUP_SUDOERS_RULE" | sudo tee "$CGROUP_SUDOERS_FILE" > /dev/null && sudo chmod 440 "$CGROUP_SUDOERS_FILE"; then
                    echo "   ✅ Cgroup sudoers rule installed at $CGROUP_SUDOERS_FILE"
                else
                    echo "   ⚠️  Failed to install cgroup sudoers rule."
                    echo "   Add manually via visudo: $CGROUP_SUDOERS_RULE"
                fi
            else
                echo "   ⚠️  Cgroup sudoers rule skipped. Add manually via visudo if needed:"
                echo "      $CGROUP_SUDOERS_RULE"
            fi
        else
            echo "   ⚠️  Failed to install cgroup helper — session isolation will be limited."
        fi
    else
        echo "⚠️  Cgroup helper skipped — session isolation will be limited."
    fi
else
    echo "ℹ️  scripts/sevorix-cgroup-helper not found — skipping."
fi

# ---------------------------------------------------------------
# Install Claude Code launcher (mount-namespace /bin/bash interception)
# ---------------------------------------------------------------
CLAUDE_LAUNCHER="/usr/local/bin/sevorix-claude-launcher"
if [ -f "scripts/sevorix-claude-launcher" ]; then
    if prompt_confirm \
        "Install Claude Code launcher to /usr/local/bin" \
        "Installs a privileged launcher that wraps 'claude' in a mount namespace,
│  binding sevsh over /bin/bash so Claude Code's Bash tool commands are
│  intercepted and validated by Sevorix — even though Claude Code calls
│  /bin/bash by absolute path rather than looking it up in PATH.
│
│  WHY THIS NEEDS ROOT: bind-mounting over /bin/bash requires CAP_SYS_ADMIN.
│  The mount namespace scopes the bind mount to just the claude session —
│  the rest of your system sees the original /bin/bash throughout.
│
│  WHEN YOU CAN SKIP THIS: if you don't use Claude Code, or if HTTP proxy
│  interception alone (network traffic only, no shell command validation)
│  is sufficient for your use case.
│
│  Writes to: $CLAUDE_LAUNCHER"; then
        if sudo cp "scripts/sevorix-claude-launcher" "$CLAUDE_LAUNCHER" && sudo chmod 755 "$CLAUDE_LAUNCHER"; then
            echo "   ✅ Claude Code launcher installed"
            CLAUDE_SUDOERS_FILE="/etc/sudoers.d/sevorix-claude"
            CLAUDE_SUDOERS_RULE="$USER ALL=(root) NOPASSWD: $CLAUDE_LAUNCHER"
            if prompt_confirm \
                "Install passwordless sudoers rule for Claude Code launcher" \
                "Allows launching claude through Sevorix without a sudo password prompt.
│  Writes to: $CLAUDE_SUDOERS_FILE
│  Rule: $CLAUDE_SUDOERS_RULE"; then
                if echo "$CLAUDE_SUDOERS_RULE" | sudo tee "$CLAUDE_SUDOERS_FILE" > /dev/null && sudo chmod 440 "$CLAUDE_SUDOERS_FILE"; then
                    echo "   ✅ Claude sudoers rule installed at $CLAUDE_SUDOERS_FILE"
                    echo "   Launch claude via: sudo sevorix-claude-launcher"
                else
                    echo "   ⚠️  Failed to install Claude sudoers rule."
                    echo "   Add manually via visudo: $CLAUDE_SUDOERS_RULE"
                fi
            else
                echo "   ⚠️  Sudoers rule skipped. Add manually via visudo if needed:"
                echo "      $CLAUDE_SUDOERS_RULE"
            fi
        else
            echo "   ⚠️  Failed to install Claude Code launcher."
        fi
    else
        echo "ℹ️  Claude Code launcher skipped — shell command interception unavailable."
    fi
else
    echo "ℹ️  scripts/sevorix-claude-launcher not found — skipping."
fi

# ---------------------------------------------------------------
# Install default config (policies + roles) via Sevorix Hub
# ---------------------------------------------------------------
if [ -n "$(ls -A "$CONFIG_DIR/policies" 2>/dev/null)" ] || [ -n "$(ls -A "$CONFIG_DIR/roles" 2>/dev/null)" ]; then
    echo "ℹ️  Existing config found in $CONFIG_DIR — keeping it."
elif prompt_confirm \
    "Pull default policies and roles from Sevorix Hub" \
    "Downloads the canonical default policy set from the public Hub registry (requires internet access).
│  Artifacts: default-policies@1.0.0, default-roles@1.0.0
│
│  ⚠️  DISCLAIMER: Default policies and roles provide minimal safeguards only.
│  To properly secure your system, critically review your use case and security
│  vulnerabilities, and curate your own policies and roles for your environment."; then
    echo "📝 Pulling default-policies from Hub..."
    if "$INSTALL_DIR/sevorix" hub pull default-policies 1.0.0 \
            -o "$CONFIG_DIR/policies/default_policies.json" 2>&1; then
        echo "   ✅ Default policies installed"
    else
        echo "   ⚠️  Failed to pull default policies — no policies installed."
        rm -f "$CONFIG_DIR/policies/default_policies.json"
    fi

    echo "📝 Pulling default-roles from Hub..."
    if "$INSTALL_DIR/sevorix" hub pull default-roles 1.0.0 \
            -o "$CONFIG_DIR/roles/default_roles.json" 2>&1; then
        echo "   ✅ Default roles installed"
    else
        echo "   ⚠️  Failed to pull default roles — no roles installed."
        rm -f "$CONFIG_DIR/roles/default_roles.json"
    fi
else
    echo "ℹ️  Skipping default config — no policies or roles installed."
fi

# ---------------------------------------------------------------
# PATH check
# ---------------------------------------------------------------
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo ""
    echo "⚠️  NOTE: $INSTALL_DIR is not in your PATH."
    echo "   Add the following to your shell config (~/.bashrc or ~/.zshrc) and restart your shell:"
    echo "   export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

echo ""
echo "✅ Installation complete!"
echo "   Run 'sevorix start' to launch the daemon."
echo "   Run 'sevorix status' to check status."
echo "   Run 'sevsh -- <command>' to run a command inside a monitored session."

# ---------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------
BUNDLE_DIR="$(basename "$PWD")"
PARENT_DIR="$(dirname "$PWD")"
TARBALL="${PARENT_DIR}/${BUNDLE_DIR}.tar.gz"
CHECKSUM="${TARBALL}.sha256"

CLEANUP_TARGETS=()
[ -f "$TARBALL" ]  && CLEANUP_TARGETS+=("$TARBALL")
[ -f "$CHECKSUM" ] && CLEANUP_TARGETS+=("$CHECKSUM")

if prompt_confirm \
    "Clean up installation files" \
    "Removes the downloaded tarball and this bundle directory."; then
    rm -f "${CLEANUP_TARGETS[@]}"
    # cd out of the bundle dir before removing it
    bash -c "cd '$PARENT_DIR' && rm -rf '$BUNDLE_DIR'" &
fi
