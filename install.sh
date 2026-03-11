#!/bin/bash
set -e

# Sevorix Watchtower Installer

BINARY_NAME="sevorix"
INSTALL_DIR="$HOME/.local/bin"
CONFIG_DIR="$HOME/.sevorix"
STATE_DIR="$HOME/.local/state/sevorix"

echo "--------------------------------------------------"
echo "🛡️  Sevorix Watchtower Installer"
echo "--------------------------------------------------"

# Create user directories
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
        echo "   Installing nightly Rust toolchain (required for eBPF kernel bytecode)..."
        rustup toolchain install nightly
    fi

    # ---------------------------------------------------------------
    # Prerequisite: rust-src component on nightly (needed for -Zbuild-std)
    # ---------------------------------------------------------------
    if ! rustup component list --toolchain nightly --installed 2>/dev/null | grep -q "rust-src"; then
        echo "   Adding rust-src to nightly toolchain..."
        rustup component add rust-src --toolchain nightly
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
        echo "   Installing bpf-linker (required for eBPF bytecode compilation)..."
        cargo install bpf-linker
    fi

    # ---------------------------------------------------------------
    # Build userspace binaries (watchtower, sevsh, eBPF daemon)
    # A single invocation builds all three.
    # ---------------------------------------------------------------
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
    if cargo +nightly build --target bpfel-unknown-none -Zbuild-std=core -p sevorix-ebpf --release; then
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

    echo "🔐 Granting eBPF capabilities to sevorix-ebpf-daemon (requires sudo)..."
    if sudo setcap cap_bpf,cap_perfmon,cap_net_admin,cap_sys_admin+ep "$INSTALL_DIR/sevorix-ebpf-daemon"; then
        echo "   ✅ Capabilities granted"
    else
        echo "   ⚠️  setcap failed — eBPF daemon may require sudo to run."
    fi

    SUDOERS_FILE="/etc/sudoers.d/sevorix-ebpf"
    SUDOERS_RULE="$USER ALL=(root) NOPASSWD: $INSTALL_DIR/sevorix-ebpf-daemon"
    echo "🔐 Installing sudoers rule for passwordless eBPF daemon launch (requires sudo)..."
    if echo "$SUDOERS_RULE" | sudo tee "$SUDOERS_FILE" > /dev/null && sudo chmod 440 "$SUDOERS_FILE"; then
        echo "   ✅ Sudoers rule installed at $SUDOERS_FILE"
    else
        echo "   ⚠️  Failed to install sudoers rule."
        echo "   Add manually via visudo: $SUDOERS_RULE"
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
    echo "🔐 Installing cgroup helper to $CGROUP_HELPER (requires sudo)..."
    if sudo cp "scripts/sevorix-cgroup-helper" "$CGROUP_HELPER" && sudo chmod 755 "$CGROUP_HELPER"; then
        echo "   ✅ Cgroup helper installed"
        CGROUP_SUDOERS_FILE="/etc/sudoers.d/sevorix-cgroup"
        CGROUP_SUDOERS_RULE="$USER ALL=(root) NOPASSWD: $CGROUP_HELPER"
        if echo "$CGROUP_SUDOERS_RULE" | sudo tee "$CGROUP_SUDOERS_FILE" > /dev/null && sudo chmod 440 "$CGROUP_SUDOERS_FILE"; then
            echo "   ✅ Cgroup sudoers rule installed at $CGROUP_SUDOERS_FILE"
        else
            echo "   ⚠️  Failed to install cgroup sudoers rule."
            echo "   Add manually via visudo: $CGROUP_SUDOERS_RULE"
        fi
    else
        echo "   ⚠️  Failed to install cgroup helper — session isolation will be limited."
    fi
else
    echo "⚠️  scripts/sevorix-cgroup-helper not found — session isolation will be limited."
fi

# ---------------------------------------------------------------
# Install default config (policies + roles) — skip if already present
# ---------------------------------------------------------------
mkdir -p "$CONFIG_DIR/policies"
mkdir -p "$CONFIG_DIR/roles"

if [ -z "$(ls -A "$CONFIG_DIR/policies" 2>/dev/null)" ]; then
    if [ -f "config/default_policies.json" ]; then
        echo "📝 Installing default policies..."
        cp "config/default_policies.json" "$CONFIG_DIR/policies/default_policies.json"
    fi
else
    echo "ℹ️  Existing policies found in $CONFIG_DIR/policies — keeping them."
fi

if [ -z "$(ls -A "$CONFIG_DIR/roles" 2>/dev/null)" ]; then
    if [ -f "config/default_roles.json" ]; then
        echo "📝 Installing default roles..."
        cp "config/default_roles.json" "$CONFIG_DIR/roles/default_roles.json"
    fi
else
    echo "ℹ️  Existing roles found in $CONFIG_DIR/roles — keeping them."
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
