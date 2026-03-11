#!/bin/bash
set -e

# Sevorix Watchtower Installer

BINARY_NAME="sevorix"
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
            echo "Usage: ./install.sh [--force]"
            echo ""
            echo "  --force  Skip all confirmation prompts (non-interactive install)"
            exit 0
            ;;
    esac
done

# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------

# prompt_confirm <title> <detail>
# Returns 0 to proceed, 1 to skip. With --force, always returns 0.
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
echo "🛡️  Sevorix Watchtower Installer"
if [ "$FORCE" -eq 1 ]; then
    echo "   Running in --force mode (no prompts)"
fi
echo "--------------------------------------------------"

# Create user directories (non-invasive, no prompt needed)
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$STATE_DIR"

SOURCE_BIN=""

# Determine Install Mode
if [ -f "Cargo.toml" ]; then
    echo "🏗️  Source code detected. Building from source..."

    # ---------------------------------------------------------------
    # Prerequisite: stable Rust toolchain
    # ---------------------------------------------------------------
    if ! command -v cargo &> /dev/null; then
        echo "❌ Error: 'cargo' not found. Install Rust from https://rustup.rs and re-run."
        exit 1
    fi

    # ---------------------------------------------------------------
    # Prerequisite: nightly toolchain (required for eBPF bytecode)
    # ---------------------------------------------------------------
    if ! cargo +nightly --version &> /dev/null; then
        if prompt_confirm \
            "Install nightly Rust toolchain" \
            "Required for eBPF kernel bytecode compilation. Runs: rustup toolchain install nightly"; then
            rustup toolchain install nightly
        else
            echo "   ⚠️  Nightly toolchain skipped — eBPF support will be unavailable."
        fi
    fi

    # ---------------------------------------------------------------
    # Prerequisite: rust-src component on nightly (needed for -Zbuild-std)
    # ---------------------------------------------------------------
    if cargo +nightly --version &> /dev/null; then
        if ! rustup component list --toolchain nightly --installed 2>/dev/null | grep -q "rust-src"; then
            if prompt_confirm \
                "Add rust-src to nightly toolchain" \
                "Needed for -Zbuild-std when compiling eBPF programs. Runs: rustup component add rust-src --toolchain nightly"; then
                rustup component add rust-src --toolchain nightly
            else
                echo "   ⚠️  rust-src skipped — eBPF bytecode compilation will be unavailable."
            fi
        fi
    fi

    # ---------------------------------------------------------------
    # Note: bpfel-unknown-none is a Tier 3 custom target — it cannot
    # be added via 'rustup target add'.  It is built on-the-fly by
    # the -Zbuild-std=core flag below, which requires only rust-src
    # (already ensured above).
    # ---------------------------------------------------------------
    # Prerequisite: bpf-linker (eBPF LLVM backend)
    # ---------------------------------------------------------------
    if ! command -v bpf-linker &> /dev/null; then
        if prompt_confirm \
            "Install bpf-linker" \
            "LLVM-based linker required for eBPF bytecode. Runs: cargo install bpf-linker (may take several minutes)"; then
            cargo install bpf-linker
        else
            echo "   ⚠️  bpf-linker skipped — eBPF support will be unavailable."
        fi
    fi

    # ---------------------------------------------------------------
    # Build userspace binaries (watchtower, sevsh, eBPF daemon)
    # A single invocation builds all three.
    # ---------------------------------------------------------------
    if prompt_confirm \
        "Build Sevorix from source" \
        "Compiles release binaries (sevorix, sevsh, sevorix-ebpf-daemon). Runs: cargo build --release --features ebpf"; then
        echo "   Compiling release build (this may take a minute)..."
        cargo build --release --features ebpf

        SOURCE_BIN="target/release/sevorix_watchtower"
        SHELL_BIN="target/release/sevsh"
        EBPF_BIN="target/release/sevorix-ebpf-daemon"

        if [ ! -f "$SOURCE_BIN" ]; then
            echo "❌ Build failed. Binary not found at $SOURCE_BIN"
            exit 1
        fi
        echo "   ✅ Userspace binaries built"

        # ---------------------------------------------------------------
        # Build eBPF kernel bytecode (loaded by daemon at runtime)
        # ---------------------------------------------------------------
        EBPF_BYTECODE="target/bpfel-unknown-none/release/sevorix-ebpf"
        echo "   Compiling eBPF kernel bytecode..."
        if cargo +nightly build --target bpfel-unknown-none -Zbuild-std=core -p sevorix-ebpf --release 2>/dev/null; then
            if [ -f "$EBPF_BYTECODE" ]; then
                echo "   ✅ eBPF kernel bytecode compiled"
            else
                echo "   ⚠️  eBPF bytecode not found after build — eBPF monitoring will be unavailable."
                EBPF_BYTECODE=""
            fi
        else
            echo "   ⚠️  eBPF bytecode build failed — eBPF monitoring will be unavailable."
            EBPF_BYTECODE=""
        fi
    else
        echo "❌ Build skipped. Cannot continue without binaries."
        exit 1
    fi

elif [ -f "sevorix" ]; then
    echo "📦 Pre-compiled binary detected."
    SOURCE_BIN="sevorix"
    SHELL_BIN="sevsh"
    EBPF_BIN="sevorix-ebpf-daemon"
    EBPF_BYTECODE="sevorix-ebpf"
else
    echo "❌ No valid installation source found."
    echo "   Run this script from the source repository or an extracted release folder."
    exit 1
fi

# ---------------------------------------------------------------
# Stop existing daemon before overwriting binaries
# ---------------------------------------------------------------
if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
    echo "🔄  Stopping any running Sevorix instances..."
    "$INSTALL_DIR/$BINARY_NAME" stop 2>/dev/null || true
    sleep 1
fi

# ---------------------------------------------------------------
# Install binaries
# ---------------------------------------------------------------
echo "🚀 Installing $BINARY_NAME to $INSTALL_DIR..."
cp "$SOURCE_BIN" "$INSTALL_DIR/$BINARY_NAME"
chmod +x "$INSTALL_DIR/$BINARY_NAME"

if [ -f "$SHELL_BIN" ]; then
    echo "🚀 Installing sevsh to $INSTALL_DIR..."
    rm -f "$INSTALL_DIR/sevsh"
    cp "$SHELL_BIN" "$INSTALL_DIR/sevsh"
    chmod +x "$INSTALL_DIR/sevsh"
else
    echo "⚠️  sevsh binary not found."
fi

if [ -n "$EBPF_BIN" ] && [ -f "$EBPF_BIN" ]; then
    echo "🚀 Installing sevorix-ebpf-daemon to $INSTALL_DIR..."
    rm -f "$INSTALL_DIR/sevorix-ebpf-daemon"
    cp "$EBPF_BIN" "$INSTALL_DIR/sevorix-ebpf-daemon"
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
    echo "ℹ️  eBPF daemon binary not found — skipping."
fi

if [ -n "$EBPF_BYTECODE" ] && [ -f "$EBPF_BYTECODE" ]; then
    echo "🚀 Installing eBPF kernel bytecode to $INSTALL_DIR..."
    rm -f "$INSTALL_DIR/sevorix-ebpf"
    cp "$EBPF_BYTECODE" "$INSTALL_DIR/sevorix-ebpf"
    echo "   ✅ eBPF bytecode installed"
else
    echo "ℹ️  eBPF kernel bytecode not available — eBPF monitoring will be unavailable."
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
    echo "⚠️  scripts/sevorix-cgroup-helper not found — session isolation will be limited."
fi

# ---------------------------------------------------------------
# Install default config (policies + roles) via Sevorix Hub
# ---------------------------------------------------------------
mkdir -p "$CONFIG_DIR/policies"
mkdir -p "$CONFIG_DIR/roles"

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
    if "$INSTALL_DIR/$BINARY_NAME" hub pull default-policies 1.0.0 \
            -o "$CONFIG_DIR/policies/default_policies.json" 2>&1; then
        echo "   ✅ Default policies installed"
    else
        echo "   ⚠️  Failed to pull default policies — no policies installed."
        rm -f "$CONFIG_DIR/policies/default_policies.json"
    fi

    echo "📝 Pulling default-roles from Hub..."
    if "$INSTALL_DIR/$BINARY_NAME" hub pull default-roles 1.0.0 \
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
