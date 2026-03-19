// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

//! Build script for sevorix-watchtower.
//!
//! Compiles eBPF programs when the `ebpf` feature is enabled.

#[cfg(feature = "ebpf")]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=sevorix-ebpf/src/main.rs");

    // Compile the eBPF program
    // Note: This requires the bpfel-unknown-none target to be available
    // In a full setup, we would use aya-build to compile the eBPF program
    // For now, we'll rely on manual compilation or skip this step
}

#[cfg(not(feature = "ebpf"))]
fn main() {}
