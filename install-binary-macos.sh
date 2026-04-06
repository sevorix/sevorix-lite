#!/bin/bash
set -e

# Sevorix Binary Installer — macOS
# Run this from an extracted release bundle containing: sevorix, sevsh

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
echo "🛡️  Sevorix Watchtower Binary Installer (macOS)"
if [ "$FORCE" -eq 1 ]; then
    echo "   Running in --force mode (no prompts)"
fi
echo "--------------------------------------------------"
echo ""
echo "ℹ️  macOS note: eBPF syscall monitoring and seccomp shell filtering"
echo "   are Linux-only features and are not included in this build."
echo "   The HTTP proxy, policy engine, sevsh, and dashboard are fully supported."

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
    echo "   Add the following to your shell config (~/.zshrc or ~/.bash_profile) and restart your shell:"
    echo "   export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

echo ""
echo "✅ Installation complete!"
echo "   Run 'sevorix start' to launch the daemon."
echo "   Run 'sevorix status' to check status."
echo "   Run 'sevsh -- <command>' to run a command inside a monitored session."
echo ""
echo "   Dashboard: http://localhost:3000/dashboard/desktop.html"

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
