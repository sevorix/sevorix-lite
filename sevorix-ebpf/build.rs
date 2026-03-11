//! Build script for sevorix-ebpf.
//!
//! Compiles eBPF programs using aya-build.

fn main() {
    // Tell cargo to invalidate the built crate whenever the kernel headers change.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/main.rs");

    // The aya-build crate will compile the eBPF programs at build time.
    // This is done via the `cargo-aya` tool or by manually invoking clang.
    //
    // For now, we rely on the workspace build to compile the eBPF program.
    // The userspace daemon will load the compiled .o file.
}
