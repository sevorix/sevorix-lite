// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Sevorix

//! Shared types between eBPF programs and userspace.
//!
//! This crate provides common data structures used by both the kernel-space
//! eBPF programs and the userspace daemon.
//!
//! # Features
//!
//! - `user`: Enable userspace support with aya crate
//! - `kernel`: Enable kernel-space support with aya-ebpf crate

// For kernel (eBPF) mode, we need no_std
#![cfg_attr(feature = "kernel", no_std)]

#[cfg(feature = "user")]
use zerocopy::{FromBytes, IntoBytes, KnownLayout};

/// Syscall event data sent from eBPF to userspace via ring buffer.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "user", derive(FromBytes, IntoBytes, KnownLayout))]
#[repr(C)]
pub struct SyscallEvent {
    /// Event type: 1 = syscall entry.
    pub event_type: u32,
    /// Process ID (kernel tgid).
    pub pid: u32,
    /// Thread ID (kernel pid).
    pub tid: u32,
    /// Padding to align to 8 bytes.
    pub _padding0: u32,
    /// Syscall number.
    pub syscall_nr: u64,
    /// Timestamp (nanoseconds since boot).
    pub timestamp: u64,
    /// First 6 arguments of the syscall.
    pub args: [u64; 6],
    /// Reserved for future use.
    pub _reserved: [u64; 2],
}

/// Network connection event data sent from eBPF to userspace.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "user", derive(FromBytes, IntoBytes, KnownLayout))]
#[repr(C)]
pub struct NetworkEvent {
    /// Event type: 2 = network connect.
    pub event_type: u32,
    /// Process ID.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Padding to align to 8 bytes.
    pub _padding0: u32,
    /// Destination IPv4 address (network byte order).
    pub dst_ip: u32,
    /// Destination port (network byte order).
    pub dst_port: u16,
    /// Protocol (TCP=6, UDP=17, etc).
    pub protocol: u8,
    /// Socket operation type (connect=0, bind=1, etc).
    pub op: u8,
    /// Timestamp (nanoseconds since boot).
    pub timestamp: u64,
    /// Source IPv4 address (network byte order).
    pub src_ip: u32,
    /// Source port (network byte order).
    pub src_port: u16,
    /// Address family (AF_INET=2, AF_INET6=10).
    pub family: u16,
    /// Reserved for future use.
    pub _reserved: [u64; 2],
}

/// Policy decision from userspace to eBPF.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "user", derive(FromBytes, IntoBytes, KnownLayout))]
#[repr(C)]
pub struct PolicyDecision {
    /// Process ID this decision applies to.
    pub pid: u32,
    /// Action: 0=allow, 1=deny, 2=audit.
    pub action: u32,
    /// Syscall number or 0 for network.
    pub syscall_nr: u64,
}

/// Network policy key for IP:port allow/deny maps.
/// Key: (dst_ip, dst_port) tuple for network filtering.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "user", derive(FromBytes, IntoBytes, KnownLayout))]
#[repr(C)]
pub struct NetworkKey {
    /// Destination IPv4 address (network byte order).
    pub dst_ip: u32,
    /// Destination port (network byte order).
    pub dst_port: u16,
    /// Protocol (TCP=6, UDP=17, 0=any).
    pub protocol: u8,
    /// Padding to 8-byte boundary.
    pub _padding: u8,
}

/// Per-process network policy key.
/// Key: (pid, dst_ip, dst_port) tuple for process-specific network filtering.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "user", derive(FromBytes, IntoBytes, KnownLayout))]
#[repr(C)]
pub struct ProcessNetworkKey {
    /// Process ID.
    pub pid: u32,
    /// Destination IPv4 address (network byte order).
    pub dst_ip: u32,
    /// Destination port (network byte order).
    pub dst_port: u16,
    /// Protocol (TCP=6, UDP=17, 0=any).
    pub protocol: u8,
    /// Padding to 8-byte boundary.
    pub _padding: u8,
}

/// Map keys for policy maps.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "user", derive(FromBytes, IntoBytes, KnownLayout))]
#[repr(C)]
pub struct PolicyKey {
    /// Process ID.
    pub pid: u32,
    /// Padding to align to 8 bytes.
    pub _padding: u32,
    /// Syscall number or connection identifier.
    pub id: u64,
}

impl SyscallEvent {
    /// Event type constant for syscall entry events.
    pub const EVENT_TYPE: u32 = 1;
    /// Event type constant for syscall exit events.
    pub const EVENT_TYPE_EXIT: u32 = 3;
    /// Size of the event in bytes.
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

impl NetworkEvent {
    /// Event type constant for network events.
    pub const EVENT_TYPE: u32 = 2;
    /// Size of the event in bytes.
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

// Implement aya::Pod for userspace when the user feature is enabled
#[cfg(feature = "user")]
unsafe impl aya::Pod for SyscallEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NetworkEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyDecision {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NetworkKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessNetworkKey {}
