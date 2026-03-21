#!/usr/bin/env python3
"""
Strip Pro-only features from Sevorix Watchtower for Lite distribution.

This script removes:
1. src/jury.rs - Pro-only file
2. All code within #[cfg(feature = "pro")] blocks
3. Pro feature references in Cargo.toml

Security: This script ensures no Pro-specific code leaks to the Lite repository.
"""

import os
import re
import sys
from pathlib import Path


def strip_cfg_pro_blocks(content: str) -> str:
    """
    Remove #[cfg(feature = "pro")] blocks from Rust source code.

    Handles:
    - Single-line cfg attributes on items (e.g., #[cfg(feature = "pro")] jury,)
    - Multi-line cfg attributes on items
    - Multi-line function/item signatures (where { comes later)
    - Nested braces within pro blocks
    """
    lines = content.split('\n')
    result_lines = []
    in_pro_block = False
    brace_depth = 0
    pending_attribute = False  # Track if we just saw a cfg(feature = "pro") attr
    waiting_for_brace = False   # Track if we're waiting for { after seeing fn/struct/etc
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if pending_attribute:
            # We saw a #[cfg(feature = "pro")] on the previous line
            # Determine what follows

            # Check if this starts a block definition (function, struct, etc.)
            is_block_start = any([
                'fn ' in stripped,
                stripped.startswith('struct '),
                stripped.startswith('enum '),
                stripped.startswith('impl '),
                stripped.startswith('trait '),
                stripped.startswith('type '),
                stripped.startswith('const '),
                stripped.startswith('static '),
            ])

            if is_block_start:
                # This starts a block - skip until we find {, then track braces
                waiting_for_brace = True
                in_pro_block = False  # Don't track braces yet
                pending_attribute = False
                i += 1
                continue
            elif '{' in line:
                # Inline block - track braces
                in_pro_block = True
                brace_depth = line.count('{') - line.count('}')
                waiting_for_brace = False
                pending_attribute = False
                if brace_depth <= 0:
                    in_pro_block = False
                i += 1
                continue
            elif stripped.endswith(',') or stripped.endswith(';'):
                # Single-line item (field or statement)
                # Skip just this one line
                pending_attribute = False
                i += 1
                continue
            else:
                # Multi-line signature - keep skipping
                i += 1
                continue

        if waiting_for_brace:
            # We're waiting for the opening brace of a pro block
            if '{' in line:
                in_pro_block = True
                brace_depth = line.count('{') - line.count('}')
                waiting_for_brace = False
                if brace_depth <= 0:
                    in_pro_block = False
            i += 1
            continue

        if not in_pro_block:
            # Check for #[cfg(feature = "pro")] start
            if stripped.startswith('#[cfg(feature = "pro")]'):
                # This line starts a pro block - skip the attribute
                pending_attribute = True
                i += 1
                continue

            # Remove #[cfg(not(feature = "pro"))] — always true in lite, unknown feature warning
            if stripped.startswith('#[cfg(not(feature = "pro"))]'):
                i += 1
                continue

            result_lines.append(line)
        else:
            # Inside a pro block - track braces
            brace_depth += line.count('{') - line.count('}')

            # Block ends when braces are balanced (depth returns to 0)
            if brace_depth <= 0:
                in_pro_block = False

            i += 1
            continue

        i += 1

    return '\n'.join(result_lines)


def strip_mod_declaration(content: str, module_name: str) -> str:
    """Remove module declaration lines for the given module."""
    # Remove both `pub mod module_name;` and `mod module_name;`
    pattern = rf'^\s*(pub\s+)?mod\s+{module_name}\s*;?\s*$'
    lines = content.split('\n')
    filtered = [line for line in lines if not re.match(pattern, line)]
    return '\n'.join(filtered)


def strip_cargo_pro_feature(content: str) -> str:
    """Remove the pro feature from Cargo.toml."""
    lines = content.split('\n')
    result_lines = []
    in_features = False
    skip_next_empty = False

    for line in lines:
        stripped = line.strip()

        if stripped == '[features]':
            in_features = True
            result_lines.append(line)
            continue

        if in_features:
            if stripped.startswith('[') and stripped.endswith(']'):
                in_features = False
            elif stripped == 'default = []':
                result_lines.append(line)
                continue
            elif stripped == 'pro = []':
                # Skip the pro feature line
                skip_next_empty = True
                continue
            elif stripped == '' and skip_next_empty:
                skip_next_empty = False
                continue

        result_lines.append(line)

    return '\n'.join(result_lines)


def process_file(filepath: Path, is_rust: bool) -> bool:
    """Process a single file, stripping pro features. Returns True if modified."""
    try:
        content = filepath.read_text()
        original = content

        if is_rust:
            # Strip cfg(feature = "pro") blocks
            content = strip_cfg_pro_blocks(content)
            # Remove jury module references
            if filepath.name != 'jury.rs':  # jury.rs will be deleted
                content = strip_mod_declaration(content, 'jury')

        if content != original:
            filepath.write_text(content)
            return True
        return False
    except Exception as e:
        print(f"Error processing {filepath}: {e}", file=sys.stderr)
        return False


def strip_yaml_pro_blocks(content: str) -> str:
    """
    Remove pro-only sections from YAML files delimited by comment markers.

    Removes blocks between (and including):
      # [pro-only-start] ... # [pro-only-end]
    """
    lines = content.split('\n')
    result = []
    in_pro_block = False
    for line in lines:
        if line.strip() == '# [pro-only-start]':
            in_pro_block = True
            continue
        if line.strip() == '# [pro-only-end]':
            in_pro_block = False
            continue
        if not in_pro_block:
            result.append(line)
    return '\n'.join(result)


def strip_html_pro_sections(content: str) -> str:
    """
    Remove pro-only sections from HTML files delimited by comment markers.

    Removes blocks between:
      <!-- Jury Configuration Card --> ... <!-- End Jury Configuration Card -->
      <!-- Jury Assessment Card --> ... <!-- End Jury Assessment Card -->

    Also removes inline JS references to jury card elements in the connect() function.
    """
    import re

    # Remove comment-delimited jury card blocks (including content between them)
    markers = [
        ("<!-- Jury Configuration Card -->", "<!-- End Jury Configuration Card -->"),
        ("<!-- Jury Assessment Card -->", "<!-- End Jury Assessment Card -->"),
    ]
    for start_marker, end_marker in markers:
        pattern = re.compile(
            re.escape(start_marker) + r'.*?' + re.escape(end_marker),
            re.DOTALL
        )
        content = pattern.sub('', content)

    # Remove inline jury card hide/show JS in connect() (lines referencing juryConfigCard / juryAssessmentCard)
    lines = content.split('\n')
    filtered = [
        line for line in lines
        if 'juryConfigCard' not in line and 'juryAssessmentCard' not in line
    ]
    return '\n'.join(filtered)


def main():
    """Main entry point."""
    # Get repository root from environment or use current directory
    repo_root = Path(os.environ.get('GITHUB_WORKSPACE', '.')).resolve()

    print(f"Processing repository at: {repo_root}")

    modified_files = []
    removed_files = []

    # 1. Remove src/jury.rs (Pro-only file)
    jury_path = repo_root / 'src' / 'jury.rs'
    if jury_path.exists():
        jury_path.unlink()
        removed_files.append(str(jury_path.relative_to(repo_root)))
        print(f"Removed: {jury_path.relative_to(repo_root)}")

    # 2. Process Rust source files
    src_dir = repo_root / 'src'
    if src_dir.exists():
        for rs_file in src_dir.rglob('*.rs'):
            if process_file(rs_file, is_rust=True):
                modified_files.append(str(rs_file.relative_to(repo_root)))
                print(f"Modified: {rs_file.relative_to(repo_root)}")

    # 3. Process test files
    tests_dir = repo_root / 'tests'
    if tests_dir.exists():
        for rs_file in tests_dir.rglob('*.rs'):
            if process_file(rs_file, is_rust=True):
                modified_files.append(str(rs_file.relative_to(repo_root)))
                print(f"Modified: {rs_file.relative_to(repo_root)}")

    # 4. Strip pro sections from static HTML
    html_files = [repo_root / 'static' / 'desktop.html']
    for html_file in html_files:
        if html_file.exists():
            content = html_file.read_text()
            original = content
            content = strip_html_pro_sections(content)
            if content != original:
                html_file.write_text(content)
                modified_files.append(str(html_file.relative_to(repo_root)))
                print(f"Modified: {html_file.relative_to(repo_root)}")

    # 5. Replace README.md with lite version
    lite_readme = repo_root / 'README_LITE.md'
    main_readme = repo_root / 'README.md'
    if lite_readme.exists():
        import shutil
        shutil.copy(lite_readme, main_readme)
        modified_files.append('README.md')
        print(f"Replaced: README.md with README_LITE.md")
    else:
        print(f"WARNING: README_LITE.md not found — README.md not replaced", file=sys.stderr)

    # 6. Update Cargo.toml
    cargo_path = repo_root / 'Cargo.toml'
    if cargo_path.exists():
        content = cargo_path.read_text()
        original = content
        content = strip_cargo_pro_feature(content)
        if content != original:
            cargo_path.write_text(content)
            modified_files.append(str(cargo_path.relative_to(repo_root)))
            print(f"Modified: {cargo_path.relative_to(repo_root)}")

    # 7. Process GitHub Actions workflows
    workflows_dir = repo_root / '.github' / 'workflows'
    if workflows_dir.exists():
        # Delete publish-lite.yml — watchtower-only, should not exist in lite repo
        publish_lite = workflows_dir / 'publish-lite.yml'
        if publish_lite.exists():
            publish_lite.unlink()
            removed_files.append('.github/workflows/publish-lite.yml')
            print(f"Removed: .github/workflows/publish-lite.yml")

        # Strip pro-only blocks and apply lite overrides to remaining workflow files
        for yml_file in sorted(workflows_dir.glob('*.yml')):
            content = yml_file.read_text()
            original = content
            content = strip_yaml_pro_blocks(content)
            # Public lite repo uses GitHub-hosted runners, not self-hosted
            content = content.replace('runs-on: self-hosted', 'runs-on: ubuntu-latest')
            if content != original:
                yml_file.write_text(content)
                modified_files.append(str(yml_file.relative_to(repo_root)))
                print(f"Modified: {yml_file.relative_to(repo_root)}")

    # 8. Summary
    print("\n=== Strip Summary ===")
    print(f"Removed files: {len(removed_files)}")
    for f in removed_files:
        print(f"  - {f}")
    print(f"Modified files: {len(modified_files)}")
    for f in modified_files:
        print(f"  - {f}")

    # 9. Verify no pro references remain (security check)
    print("\n=== Security Verification ===")
    pro_patterns = [
        r'jury',
        r'#\[cfg\(feature\s*=\s*"pro"\)\]',
    ]

    issues_found = []
    check_files = list((repo_root / 'src').rglob('*.rs')) + \
                  list((repo_root / 'tests').rglob('*.rs')) + \
                  list((repo_root / 'static').rglob('*.html')) + \
                  [repo_root / 'README.md']
    for check_file in check_files:
        if not check_file.exists():
            continue
        content = check_file.read_text()
        for pattern in pro_patterns:
            matches = re.findall(pattern, content)
            if matches:
                issues_found.append(f"{check_file.relative_to(repo_root)}: found {pattern}")

    if issues_found:
        print("WARNING: Pro references may still exist:")
        for issue in issues_found:
            print(f"  {issue}")
        print("\nManual review recommended.")
    else:
        print("✓ No pro-specific references found in source files")

    print("\nDone!")


if __name__ == '__main__':
    main()