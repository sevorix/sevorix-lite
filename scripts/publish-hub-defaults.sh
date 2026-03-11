#!/bin/bash
set -e

# Publishes the canonical default policies and roles to Sevorix Hub.
# Run this from the repo root after `sevorix hub login`.
#
# Usage:
#   ./scripts/publish-hub-defaults.sh [--hub-url <url>] [--version <version>]
#
# Defaults:
#   --version  1.0.0
#   --hub-url  (uses sevorix default: https://sevorix-hub-...)

VERSION="1.0.0"
HUB_URL_ARG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --hub-url) HUB_URL_ARG="--hub-url $2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

SEVORIX="${SEVORIX:-sevorix}"

echo "Publishing default Sevorix artifacts to Hub at version $VERSION..."
echo ""

echo "📤 Pushing default-policies..."
$SEVORIX hub push \
    --name default-policies \
    --version "$VERSION" \
    --file config/default_policies.json \
    --description "Default Sevorix Watchtower policy set — blocks destructive SQL/shell commands and flags sensitive patterns" \
    --tag defaults --tag policies \
    --visibility public \
    --artifact-type artifact \
    $HUB_URL_ARG

echo ""
echo "📤 Pushing default-roles..."
$SEVORIX hub push \
    --name default-roles \
    --version "$VERSION" \
    --file config/default_roles.json \
    --description "Default Sevorix Watchtower role definitions" \
    --tag defaults --tag roles \
    --visibility public \
    --artifact-type artifact \
    $HUB_URL_ARG

echo ""
echo "✅ Done. Artifacts published:"
echo "   default-policies@$VERSION"
echo "   default-roles@$VERSION"
