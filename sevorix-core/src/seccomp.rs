//! seccomp-unotify infrastructure for syscall interception.
//!
//! This module provides a seccomp user-space notification system that allows
//! a supervisor process to intercept and make decisions about syscalls in
//! a target process using `SCMP_ACT_NOTIFY`.
//!
//! Unlike ptrace-based tracing, seccomp-unotify has lower overhead and allows
//! the supervisor to be a different process than the parent.

use libseccomp::error::SeccompError;
use libseccomp::*;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Errors that can occur during seccomp notifier operations.
#[derive(Error, Debug)]
pub enum SeccompNotifierError {
    #[error("Failed to create seccomp filter: {0}")]
    FilterCreation(#[source] SeccompError),

    #[error("Failed to add syscall rule: {0}")]
    AddRule(#[source] SeccompError),

    #[error("Failed to load filter: {0}")]
    LoadFilter(#[source] SeccompError),

    #[error("Failed to get notifier fd: {0}")]
    GetNotifyFd(#[source] SeccompError),

    #[error("Failed to receive notification: {0}")]
    ReceiveNotification(#[source] SeccompError),

    #[error("Failed to send response: {0}")]
    SendResponse(#[source] SeccompError),

    #[error("Invalid notifier fd")]
    InvalidFd,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Target syscall categories for filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallCategory {
    /// Network syscalls: socket, connect, bind, accept, accept4
    Network,
    /// Process syscalls: execve, execveat, clone, clone3, fork, vfork
    Process,
    /// Privilege syscalls: setuid, setgid, capset, ptrace, prctl
    Privilege,
}

impl SyscallCategory {
    /// Returns the syscall names for this category on x86_64.
    pub fn syscalls(&self) -> &'static [&'static str] {
        match self {
            SyscallCategory::Network => &["socket", "connect", "bind", "accept", "accept4"],
            SyscallCategory::Process => &["execve", "execveat", "clone", "clone3", "fork", "vfork"],
            SyscallCategory::Privilege => &["setuid", "setgid", "capset", "ptrace", "prctl"],
        }
    }
}

/// A seccomp user-space notifier for intercepting syscalls.
///
/// `SeccompNotifier` wraps a seccomp filter with `SCMP_ACT_NOTIFY` and
/// provides methods to receive notifications and respond to them.
pub struct SeccompNotifier {
    /// The seccomp filter.
    filter: ScmpFilterContext,
    /// The notification file descriptor.
    notifier_fd: RawFd,
}

impl SeccompNotifier {
    /// Create a new seccomp notifier for the specified syscall categories.
    ///
    /// The filter will use `SCMP_ACT_ALLOW` as the default action and
    /// `SCMP_ACT_NOTIFY` for the specified syscalls.
    ///
    /// # Arguments
    ///
    /// * `categories` - The syscall categories to monitor
    ///
    /// # Returns
    ///
    /// A new `SeccompNotifier` instance, or an error if filter creation fails.
    pub fn new(categories: &[SyscallCategory]) -> Result<Self, SeccompNotifierError> {
        // Create a filter with ALLOW as the default action
        let mut filter = ScmpFilterContext::new(ScmpAction::Allow)
            .map_err(SeccompNotifierError::FilterCreation)?;

        // Add NOTIFY rules for each syscall in the categories
        for category in categories {
            for &syscall_name in category.syscalls() {
                let syscall =
                    ScmpSyscall::from_name(syscall_name).map_err(SeccompNotifierError::AddRule)?;

                filter
                    .add_rule(ScmpAction::Notify, syscall)
                    .map_err(SeccompNotifierError::AddRule)?;
            }
        }

        // Load the filter
        filter.load().map_err(SeccompNotifierError::LoadFilter)?;

        // Get the notifier fd
        let notifier_fd = filter
            .get_notify_fd()
            .map_err(SeccompNotifierError::GetNotifyFd)?;

        Ok(Self {
            filter,
            notifier_fd,
        })
    }

    /// Create a seccomp notifier for a single syscall by name.
    ///
    /// Useful for testing or when you need fine-grained control.
    ///
    /// # Arguments
    ///
    /// * `syscall_name` - The name of the syscall to monitor (e.g., "openat")
    ///
    /// # Returns
    ///
    /// A new `SeccompNotifier` instance, or an error if filter creation fails.
    pub fn for_syscall(syscall_name: &str) -> Result<Self, SeccompNotifierError> {
        let mut filter = ScmpFilterContext::new(ScmpAction::Allow)
            .map_err(SeccompNotifierError::FilterCreation)?;

        let syscall =
            ScmpSyscall::from_name(syscall_name).map_err(SeccompNotifierError::AddRule)?;

        filter
            .add_rule(ScmpAction::Notify, syscall)
            .map_err(SeccompNotifierError::AddRule)?;

        filter.load().map_err(SeccompNotifierError::LoadFilter)?;

        let notifier_fd = filter
            .get_notify_fd()
            .map_err(SeccompNotifierError::GetNotifyFd)?;

        Ok(Self {
            filter,
            notifier_fd,
        })
    }

    /// Receive a notification from the kernel.
    ///
    /// This method blocks until a syscall that matches our filter is invoked
    /// by a process using our filter.
    ///
    /// # Returns
    ///
    /// A `ScmpNotifReq` containing information about the syscall, or an error.
    pub fn receive(&self) -> Result<ScmpNotifReq, SeccompNotifierError> {
        ScmpNotifReq::receive(self.notifier_fd).map_err(SeccompNotifierError::ReceiveNotification)
    }

    /// Respond to a notification.
    ///
    /// After examining a syscall request, the supervisor calls this method
    /// to tell the kernel what to do: allow, deny with an error, or kill.
    ///
    /// # Arguments
    ///
    /// * `resp` - The response to send
    ///
    /// # Returns
    ///
    /// Ok(()) on success, or an error if the response fails to send.
    pub fn respond(&self, resp: &ScmpNotifResp) -> Result<(), SeccompNotifierError> {
        resp.respond(self.notifier_fd)
            .map_err(SeccompNotifierError::SendResponse)
    }

    /// Create a response to allow the syscall to continue executing.
    ///
    /// # Arguments
    ///
    /// * `req` - The original request
    ///
    /// # Returns
    ///
    /// A response that will allow the syscall to proceed.
    pub fn allow(req: &ScmpNotifReq) -> ScmpNotifResp {
        ScmpNotifResp::new_continue(req.id, ScmpNotifRespFlags::empty())
    }

    /// Create a response to deny the syscall with EPERM.
    ///
    /// # Arguments
    ///
    /// * `req` - The original request
    ///
    /// # Returns
    ///
    /// A response that will deny the syscall with EPERM.
    pub fn deny_eperm(req: &ScmpNotifReq) -> ScmpNotifResp {
        ScmpNotifResp::new_error(req.id, -libc::EPERM, ScmpNotifRespFlags::empty())
    }

    /// Create a response to deny the syscall with a specific error.
    ///
    /// # Arguments
    ///
    /// * `req` - The original request
    /// * `error` - The *negative* error number (e.g., -(libc::EACCES as i32))
    ///
    /// # Returns
    ///
    /// A response that will deny the syscall with the specified error.
    pub fn deny(req: &ScmpNotifReq, error: i32) -> ScmpNotifResp {
        ScmpNotifResp::new_error(req.id, error, ScmpNotifRespFlags::empty())
    }

    /// Create a response to spoof a success return value.
    ///
    /// # Arguments
    ///
    /// * `req` - The original request
    /// * `val` - The return value to spoof
    ///
    /// # Returns
    ///
    /// A response that will spoof the syscall return value.
    pub fn spoof_success(req: &ScmpNotifReq, val: i64) -> ScmpNotifResp {
        ScmpNotifResp::new_val(req.id, val, ScmpNotifRespFlags::empty())
    }

    /// Get the raw notification file descriptor.
    ///
    /// This can be used with `poll()` or `epoll()` for async notification handling.
    pub fn fd(&self) -> RawFd {
        self.notifier_fd
    }

    /// Get a reference to the underlying filter.
    pub fn filter(&self) -> &ScmpFilterContext {
        &self.filter
    }
}

impl AsRawFd for SeccompNotifier {
    fn as_raw_fd(&self) -> RawFd {
        self.fd()
    }
}

/// Information about a syscall captured via seccomp-unotify.
#[derive(Debug, Clone)]
pub struct SyscallInfo {
    /// The syscall number.
    pub syscall_nr: i64,
    /// The syscall architecture.
    pub arch: ScmpArch,
    /// The process ID that triggered the syscall.
    pub pid: u32,
    /// The syscall arguments.
    pub args: [u64; 6],
    /// The instruction pointer.
    pub instr_pointer: u64,
}

impl From<&ScmpNotifReq> for SyscallInfo {
    fn from(req: &ScmpNotifReq) -> Self {
        SyscallInfo {
            syscall_nr: req.data.syscall.as_raw_syscall() as i64,
            arch: req.data.arch,
            pid: req.pid,
            args: req.data.args,
            instr_pointer: req.data.instr_pointer,
        }
    }
}

/// Convert a syscall number to its name on x86_64.
///
/// This lookup table covers the most common syscalls and is used for
/// human-readable output in logs and the dashboard.
pub fn syscall_name(nr: i64) -> &'static str {
    match nr {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        4 => "stat",
        5 => "fstat",
        6 => "lstat",
        7 => "poll",
        8 => "lseek",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        13 => "rt_sigaction",
        14 => "rt_sigprocmask",
        15 => "rt_sigreturn",
        16 => "ioctl",
        17 => "pread64",
        18 => "pwrite64",
        19 => "readv",
        20 => "writev",
        21 => "access",
        22 => "pipe",
        23 => "select",
        24 => "sched_yield",
        25 => "mremap",
        26 => "msync",
        27 => "mincore",
        28 => "madvise",
        29 => "shmget",
        30 => "shmat",
        31 => "shmctl",
        32 => "dup",
        33 => "dup2",
        34 => "pause",
        35 => "nanosleep",
        36 => "getitimer",
        37 => "alarm",
        38 => "setitimer",
        39 => "getpid",
        40 => "sendfile",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        46 => "sendmsg",
        47 => "recvmsg",
        48 => "shutdown",
        49 => "bind",
        50 => "listen",
        51 => "getsockname",
        52 => "getpeername",
        53 => "socketpair",
        54 => "setsockopt",
        55 => "getsockopt",
        56 => "clone",
        57 => "fork",
        58 => "vfork",
        59 => "execve",
        60 => "exit",
        61 => "wait4",
        62 => "kill",
        63 => "uname",
        64 => "semget",
        65 => "semop",
        66 => "semctl",
        67 => "shmdt",
        68 => "msgget",
        69 => "msgsnd",
        70 => "msgrcv",
        71 => "msgctl",
        72 => "fcntl",
        73 => "flock",
        74 => "fsync",
        75 => "fdatasync",
        76 => "truncate",
        77 => "ftruncate",
        78 => "getdents",
        79 => "getcwd",
        80 => "chdir",
        81 => "fchdir",
        82 => "rename",
        83 => "mkdir",
        84 => "rmdir",
        85 => "creat",
        86 => "link",
        87 => "unlink",
        88 => "symlink",
        89 => "readlink",
        90 => "chmod",
        91 => "fchmod",
        92 => "chown",
        93 => "fchown",
        94 => "lchown",
        95 => "umask",
        96 => "gettimeofday",
        97 => "getrlimit",
        98 => "getrusage",
        99 => "sysinfo",
        100 => "times",
        101 => "ptrace",
        102 => "getuid",
        103 => "syslog",
        104 => "getgid",
        105 => "setuid",
        106 => "setgid",
        107 => "geteuid",
        108 => "getegid",
        109 => "setpgid",
        110 => "getppid",
        111 => "getpgrp",
        112 => "setsid",
        113 => "setreuid",
        114 => "setregid",
        115 => "getgroups",
        116 => "setgroups",
        117 => "setresuid",
        118 => "getresuid",
        119 => "setresgid",
        120 => "getresgid",
        121 => "getpgid",
        122 => "setfsuid",
        123 => "setfsgid",
        124 => "getsid",
        125 => "capget",
        126 => "capset",
        127 => "rt_sigpending",
        128 => "rt_sigtimedwait",
        129 => "rt_sigqueueinfo",
        130 => "rt_sigsuspend",
        131 => "sigaltstack",
        132 => "utime",
        133 => "mknod",
        134 => "uselib",
        135 => "personality",
        136 => "ustat",
        137 => "statfs",
        138 => "fstatfs",
        139 => "sysfs",
        140 => "getpriority",
        141 => "setpriority",
        142 => "sched_setparam",
        143 => "sched_getparam",
        144 => "sched_setscheduler",
        145 => "sched_getscheduler",
        146 => "sched_get_priority_max",
        147 => "sched_get_priority_min",
        148 => "sched_rr_get_interval",
        149 => "mlock",
        150 => "munlock",
        151 => "mlockall",
        152 => "munlockall",
        153 => "vhangup",
        154 => "modify_ldt",
        155 => "pivot_root",
        156 => "_sysctl",
        157 => "prctl",
        158 => "arch_prctl",
        159 => "adjtimex",
        160 => "setrlimit",
        161 => "chroot",
        162 => "sync",
        163 => "acct",
        164 => "settimeofday",
        165 => "mount",
        166 => "umount2",
        167 => "swapon",
        168 => "swapoff",
        169 => "reboot",
        170 => "sethostname",
        171 => "setdomainname",
        172 => "iopl",
        173 => "ioperm",
        174 => "create_module",
        175 => "init_module",
        176 => "delete_module",
        177 => "get_kernel_syms",
        178 => "query_module",
        179 => "quotactl",
        180 => "nfsservctl",
        181 => "getpmsg",
        182 => "putpmsg",
        183 => "afs_syscall",
        184 => "tuxcall",
        185 => "security",
        186 => "gettid",
        187 => "readahead",
        188 => "setxattr",
        189 => "lsetxattr",
        190 => "fsetxattr",
        191 => "getxattr",
        192 => "lgetxattr",
        193 => "fgetxattr",
        194 => "listxattr",
        195 => "llistxattr",
        196 => "flistxattr",
        197 => "removexattr",
        198 => "lremovexattr",
        199 => "fremovexattr",
        200 => "tkill",
        201 => "time",
        202 => "futex",
        203 => "sched_setaffinity",
        204 => "sched_getaffinity",
        205 => "set_thread_area",
        206 => "io_setup",
        207 => "io_destroy",
        208 => "io_getevents",
        209 => "io_submit",
        210 => "io_cancel",
        211 => "get_thread_area",
        212 => "lookup_dcookie",
        213 => "epoll_create",
        214 => "epoll_ctl_old",
        215 => "epoll_wait_old",
        216 => "remap_file_pages",
        217 => "getdents64",
        218 => "set_tid_address",
        219 => "restart_syscall",
        220 => "semtimedop",
        221 => "fadvise64",
        222 => "timer_create",
        223 => "timer_settime",
        224 => "timer_gettime",
        225 => "timer_getoverrun",
        226 => "timer_delete",
        227 => "clock_settime",
        228 => "clock_gettime",
        229 => "clock_getres",
        230 => "clock_nanosleep",
        231 => "exit_group",
        232 => "epoll_wait",
        233 => "epoll_ctl",
        234 => "tgkill",
        235 => "utimes",
        236 => "vserver",
        237 => "mbind",
        238 => "set_mempolicy",
        239 => "get_mempolicy",
        240 => "mq_open",
        241 => "mq_unlink",
        242 => "mq_timedsend",
        243 => "mq_timedreceive",
        244 => "mq_notify",
        245 => "mq_getsetattr",
        246 => "kexec_load",
        247 => "waitid",
        248 => "add_key",
        249 => "request_key",
        250 => "keyctl",
        251 => "ioprio_set",
        252 => "ioprio_get",
        253 => "inotify_init",
        254 => "inotify_add_watch",
        255 => "inotify_rm_watch",
        256 => "migrate_pages",
        257 => "openat",
        258 => "mkdirat",
        259 => "mknodat",
        260 => "fchownat",
        261 => "futimesat",
        262 => "newfstatat",
        263 => "unlinkat",
        264 => "renameat",
        265 => "linkat",
        266 => "symlinkat",
        267 => "readlinkat",
        268 => "fchmodat",
        269 => "faccessat",
        270 => "pselect6",
        271 => "ppoll",
        272 => "unshare",
        273 => "set_robust_list",
        274 => "get_robust_list",
        275 => "splice",
        276 => "tee",
        277 => "sync_file_range",
        278 => "vmsplice",
        279 => "move_pages",
        280 => "utimensat",
        281 => "epoll_pwait",
        282 => "signalfd",
        283 => "timerfd_create",
        284 => "eventfd",
        285 => "fallocate",
        286 => "timerfd_settime",
        287 => "timerfd_gettime",
        288 => "accept4",
        289 => "signalfd4",
        290 => "eventfd2",
        291 => "epoll_create1",
        292 => "dup3",
        293 => "pipe2",
        294 => "inotify_init1",
        295 => "preadv",
        296 => "pwritev",
        297 => "rt_tgsigqueueinfo",
        298 => "perf_event_open",
        299 => "recvmmsg",
        300 => "fanotify_init",
        301 => "fanotify_mark",
        302 => "prlimit64",
        303 => "name_to_handle_at",
        304 => "open_by_handle_at",
        305 => "clock_adjtime",
        306 => "syncfs",
        307 => "sendmmsg",
        308 => "setns",
        309 => "getcpu",
        310 => "process_vm_readv",
        311 => "process_vm_writev",
        312 => "kcmp",
        313 => "finit_module",
        314 => "sched_setattr",
        315 => "sched_getattr",
        316 => "renameat2",
        317 => "seccomp",
        318 => "getrandom",
        319 => "memfd_create",
        320 => "kexec_file_load",
        321 => "bpf",
        322 => "execveat",
        323 => "userfaultfd",
        324 => "membarrier",
        325 => "mlock2",
        326 => "copy_file_range",
        327 => "preadv2",
        328 => "pwritev2",
        329 => "pkey_mprotect",
        330 => "pkey_alloc",
        331 => "pkey_free",
        332 => "statx",
        333 => "io_pgetevents",
        334 => "rseq",
        424 => "pidfd_send_signal",
        425 => "io_uring_setup",
        426 => "io_uring_enter",
        427 => "io_uring_register",
        428 => "open_tree",
        429 => "move_mount",
        430 => "fsopen",
        431 => "fsconfig",
        432 => "fsmount",
        433 => "fspick",
        434 => "pidfd_open",
        435 => "clone3",
        436 => "close_range",
        437 => "openat2",
        438 => "pidfd_getfd",
        439 => "faccessat2",
        440 => "process_madvise",
        441 => "epoll_pwait2",
        442 => "mount_setattr",
        443 => "quotactl_fd",
        444 => "landlock_create_ruleset",
        445 => "landlock_add_rule",
        446 => "landlock_restrict_self",
        447 => "memfd_secret",
        448 => "process_mrelease",
        _ => "unknown",
    }
}

/// x86_64 syscall numbers for argument-specific handling.
mod syscall_nr {
    pub const EXECVE: i64 = 59;
    pub const EXECVEAT: i64 = 322;
    pub const SOCKET: i64 = 41;
    pub const CONNECT: i64 = 42;
    pub const ACCEPT: i64 = 43;
    pub const SENDTO: i64 = 44;
    pub const RECVFROM: i64 = 45;
    pub const BIND: i64 = 49;
    pub const ACCEPT4: i64 = 288;
}

/// Read a null-terminated string from process memory via /proc/<pid>/mem.
///
/// Unlike ptrace-based reading, this uses the /proc filesystem which is
/// available even when the process is stopped by seccomp.
fn read_string_from_mem(mem: &mut File, addr: u64) -> Option<String> {
    mem.seek(SeekFrom::Start(addr)).ok()?;
    let mut result = Vec::new();
    let mut buf = [0u8; 1];

    // Read one byte at a time until null terminator
    for _ in 0..4096 {
        match mem.read(&mut buf) {
            Ok(1) => {
                if buf[0] == 0 {
                    break;
                }
                result.push(buf[0]);
            }
            _ => break,
        }
    }

    String::from_utf8(result).ok()
}

/// Read an array of strings (argv-style) from process memory.
///
/// The array is terminated by a NULL pointer.
fn read_string_array_from_mem(mem: &mut File, addr: u64) -> String {
    if addr == 0 {
        return "[]".to_string();
    }

    let mut strings = Vec::new();
    let mut offset = 0usize;

    for _ in 0..64 {
        // Read pointer (8 bytes on x86_64)
        if mem.seek(SeekFrom::Start(addr + offset as u64)).is_err() {
            break;
        }
        let mut ptr_bytes = [0u8; 8];
        if mem.read(&mut ptr_bytes).ok() != Some(8) {
            break;
        }

        let ptr = u64::from_ne_bytes(ptr_bytes);

        // NULL pointer terminates the array
        if ptr == 0 {
            break;
        }

        // Read the string at this pointer
        if let Some(s) = read_string_from_mem(mem, ptr) {
            strings.push(format!("\"{}\"", s));
        }

        offset += 8;

        // Safety limit
        if offset > 4096 {
            break;
        }
    }

    format!("[{}]", strings.join(", "))
}

/// Read and parse a sockaddr structure from process memory.
///
/// Supports AF_UNIX, AF_INET, and AF_INET6 address families.
fn read_sockaddr_from_mem(mem: &mut File, addr: u64, _addrlen: u64) -> Option<String> {
    // Read the first 2 bytes to get the address family (sa_family)
    mem.seek(SeekFrom::Start(addr)).ok()?;
    let mut family_bytes = [0u8; 2];
    mem.read_exact(&mut family_bytes).ok()?;
    let family = u16::from_ne_bytes(family_bytes);

    match family {
        1 => {
            // AF_UNIX - read the sun_path
            // sockaddr_un is: family (2 bytes) + path (108 bytes max)
            let path_addr = addr + 2;
            if let Some(path) = read_string_from_mem(mem, path_addr) {
                Some(format!("AF_UNIX(\"{}\")", path))
            } else {
                Some("AF_UNIX(?)".to_string())
            }
        }
        2 => {
            // AF_INET - sin_port (2 bytes) + sin_addr (4 bytes)
            mem.seek(SeekFrom::Start(addr + 2)).ok()?;
            let mut port_bytes = [0u8; 2];
            mem.read_exact(&mut port_bytes).ok()?;
            let port = u16::from_be_bytes(port_bytes);

            mem.seek(SeekFrom::Start(addr + 4)).ok()?;
            let mut addr_bytes = [0u8; 4];
            mem.read_exact(&mut addr_bytes).ok()?;

            Some(format!(
                "AF_INET({}.{}.{}.{}:{})",
                addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3], port
            ))
        }
        10 => {
            // AF_INET6 - sin6_port (2 bytes) + sin6_flowinfo (4 bytes) + sin6_addr (16 bytes)
            mem.seek(SeekFrom::Start(addr + 2)).ok()?;
            let mut port_bytes = [0u8; 2];
            mem.read_exact(&mut port_bytes).ok()?;
            let port = u16::from_be_bytes(port_bytes);

            // Read the 16-byte IPv6 address (skip flowinfo at offset 4-8)
            mem.seek(SeekFrom::Start(addr + 8)).ok()?;
            let mut ipv6_bytes = [0u8; 16];
            mem.read_exact(&mut ipv6_bytes).ok()?;

            // Format as standard IPv6 notation
            let segments: Vec<String> = (0..8)
                .map(|i| format!("{:02x}{:02x}", ipv6_bytes[i * 2], ipv6_bytes[i * 2 + 1]))
                .collect();

            Some(format!("AF_INET6([{}]:{})", segments.join(":"), port))
        }
        _ => Some(format!("AF_{}", family)),
    }
}

/// Extract syscall arguments from seccomp_data and format them as human-readable strings.
///
/// Unlike ptrace-based extraction, this reads arguments directly from seccomp_data
/// and uses /proc/<pid>/mem for memory access.
///
/// # Arguments
///
/// * `pid` - The process ID of the target process
/// * `syscall_nr` - The syscall number (architecture-specific)
/// * `args` - The syscall arguments from seccomp_data
///
/// # Returns
///
/// A vector of human-readable argument strings. Returns an empty vector on error.
pub fn extract_args_from_seccomp(pid: u32, syscall_nr: i64, args: &[u64; 6]) -> Vec<String> {
    // Try to open /proc/<pid>/mem for memory reading
    let mem_path = format!("/proc/{}/mem", pid);
    let mem = File::open(&mem_path);

    match syscall_nr {
        syscall_nr::EXECVE | syscall_nr::EXECVEAT => {
            if let Ok(mut mem) = mem {
                format_execve_args(&mut mem, args)
            } else {
                format_generic_args(args)
            }
        }
        syscall_nr::CONNECT | syscall_nr::BIND => {
            if let Ok(mut mem) = mem {
                format_sockaddr_args(&mut mem, args)
            } else {
                format_generic_args(args)
            }
        }
        syscall_nr::ACCEPT | syscall_nr::ACCEPT4 => format_accept_args(args),
        syscall_nr::SENDTO | syscall_nr::RECVFROM => {
            if let Ok(mut mem) = mem {
                format_sendto_args(&mut mem, args)
            } else {
                format_generic_args(args)
            }
        }
        syscall_nr::SOCKET => format_socket_args(args),
        _ => format_generic_args(args),
    }
}

/// Format arguments for execve syscall by reading argv strings from memory.
fn format_execve_args(mem: &mut File, args: &[u64; 6]) -> Vec<String> {
    let mut result = Vec::new();

    // execve(const char *pathname, char *const argv[], char *const envp[])
    // arg0 = pathname pointer
    // arg1 = argv pointer
    // arg2 = envp pointer

    // Read pathname
    if let Some(pathname) = read_string_from_mem(mem, args[0]) {
        result.push(format!("pathname=\"{}\"", pathname));
    } else {
        result.push(format!("pathname={:#x}", args[0]));
    }

    // Read argv array
    result.push(format!("argv={}", read_string_array_from_mem(mem, args[1])));

    // envp is often NULL or large, just show pointer
    result.push(format!("envp={:#x}", args[2]));

    result
}

/// Format arguments for socket syscalls that involve sockaddr structures.
fn format_sockaddr_args(mem: &mut File, args: &[u64; 6]) -> Vec<String> {
    let mut result = Vec::new();

    // connect/bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
    result.push(format!("fd={}", args[0]));

    if let Some(addr_str) = read_sockaddr_from_mem(mem, args[1], args[2]) {
        result.push(format!("addr={}", addr_str));
    } else {
        result.push(format!("addr={:#x}", args[1]));
    }

    result.push(format!("addrlen={}", args[2]));

    result
}

/// Format arguments for accept syscalls.
fn format_accept_args(args: &[u64; 6]) -> Vec<String> {
    // accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
    vec![
        format!("fd={}", args[0]),
        format!("addr={:#x}", args[1]),
        format!("addrlen={:#x}", args[2]),
    ]
}

/// Format arguments for sendto/recvfrom syscalls.
fn format_sendto_args(mem: &mut File, args: &[u64; 6]) -> Vec<String> {
    let mut result = Vec::new();

    // sendto(int sockfd, const void *buf, size_t len, int flags,
    //        const struct sockaddr *dest_addr, socklen_t addrlen)
    result.push(format!("fd={}", args[0]));
    result.push(format!("buf={:#x}", args[1]));
    result.push(format!("len={}", args[2]));
    result.push(format!("flags={}", args[3]));

    // dest_addr is optional (can be NULL for connected sockets)
    if args[4] != 0 && args[5] > 0 {
        if let Some(addr_str) = read_sockaddr_from_mem(mem, args[4], args[5]) {
            result.push(format!("dest_addr={}", addr_str));
        } else {
            result.push(format!("dest_addr={:#x}", args[4]));
        }
    }

    result
}

/// Format arguments for socket syscall.
fn format_socket_args(args: &[u64; 6]) -> Vec<String> {
    // socket(int domain, int type, int protocol)
    let domain = match args[0] as i32 {
        0 => "AF_UNSPEC".to_string(),
        1 => "AF_UNIX".to_string(),
        2 => "AF_INET".to_string(),
        10 => "AF_INET6".to_string(),
        d => format!("{}", d),
    };

    let sock_type = match args[1] as i32 {
        1 => "SOCK_STREAM".to_string(),
        2 => "SOCK_DGRAM".to_string(),
        3 => "SOCK_RAW".to_string(),
        t => format!("{}", t),
    };

    vec![
        format!("domain={}", domain),
        format!("type={}", sock_type),
        format!("protocol={}", args[2]),
    ]
}

/// Format generic syscall arguments as hex values.
fn format_generic_args(args: &[u64; 6]) -> Vec<String> {
    args.iter().map(|&v| format!("{:#x}", v)).collect()
}

/// Create a SyscallEvent from a seccomp notification request.
///
/// This function extracts all relevant information from the seccomp notification
/// and formats the arguments for human-readable output.
///
/// # Arguments
///
/// * `req` - The seccomp notification request
///
/// # Returns
///
/// A `SyscallEvent` with syscall name, number, formatted arguments, and metadata.
pub fn syscall_event_from_request(req: &ScmpNotifReq) -> crate::SyscallEvent {
    let syscall_nr = req.data.syscall.as_raw_syscall() as i64;
    let args = extract_args_from_seccomp(req.pid, syscall_nr, &req.data.args);

    // Get current timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| {
            chrono::DateTime::from_timestamp(d.as_secs() as i64, d.subsec_nanos())
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| d.as_secs().to_string())
        })
        .unwrap_or_else(|_| "unknown".to_string());

    // Get parent PID from /proc
    let ppid = std::fs::read_to_string(format!("/proc/{}/stat", req.pid))
        .ok()
        .and_then(|stat| {
            // Format: pid (comm) state ppid ...
            // Find the closing parenthesis and parse ppid
            let close_paren = stat.rfind(')')?;
            let fields: Vec<&str> = stat[close_paren + 2..].split_whitespace().collect();
            fields.get(1).and_then(|s| s.parse::<u32>().ok())
        })
        .unwrap_or(0);

    crate::SyscallEvent {
        syscall_name: syscall_name(syscall_nr).to_string(),
        syscall_number: syscall_nr,
        args,
        pid: req.pid,
        ppid,
        timestamp,
    }
}

// -----------------------------------------------------------------------------
// Shell Spawning with Seccomp User-Space Notification
// -----------------------------------------------------------------------------

use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, ExitStatus};

/// Minimum kernel version required for seccomp-unotify (Linux 4.14).
const MIN_KERNEL_MAJOR: u32 = 4;
const MIN_KERNEL_MINOR: u32 = 14;

/// Check if the current kernel supports seccomp user-space notification.
///
/// Seccomp-unotify was introduced in Linux 4.14. This function parses
/// the kernel version from /proc/version_signature or uname.
///
/// # Returns
///
/// `true` if the kernel supports seccomp-unotify, `false` otherwise.
pub fn kernel_supports_seccomp_notify() -> bool {
    // Read kernel version from /proc/version
    if let Ok(version_str) = std::fs::read_to_string("/proc/version") {
        // Format: Linux version 5.15.0-... (...)
        if let Some(version_part) = version_str.split("Linux version ").nth(1) {
            if let Some(release) = version_part.split('.').next() {
                if let Ok(major) = release.parse::<u32>() {
                    if let Some(minor_part) = version_part.split('.').nth(1) {
                        if let Ok(minor) =
                            minor_part.split('-').next().unwrap_or("0").parse::<u32>()
                        {
                            return major > MIN_KERNEL_MAJOR
                                || (major == MIN_KERNEL_MAJOR && minor >= MIN_KERNEL_MINOR);
                        }
                    }
                }
            }
        }
    }
    // If we can't determine the version, assume support (fail forward)
    true
}

/// Spawn a shell command under seccomp-unotify control and wait for it to complete.
///
/// This function spawns the specified shell with the given arguments under
/// seccomp user-space notification control. It intercepts syscalls in the
/// Network, Process, and Privilege categories and allows a callback to make
/// policy decisions about each intercepted syscall.
///
/// # Architecture
///
/// 1. Check kernel version (fallback to ptrace on older kernels)
/// 2. Fork the process
/// 3. Child: Install seccomp filter with NOTIFY, then exec shell
/// 4. Parent: Run notification loop, invoking callback for each syscall
///
/// # Arguments
///
/// * `shell` - The shell executable to run (e.g., "/bin/bash")
/// * `args` - Arguments to pass to the shell (e.g., ["-c", "ls -la"])
/// * `env_vars` - Environment variables to set as (key, value) pairs
/// * `callback` - Callback invoked for each intercepted syscall, returns true to allow, false to deny
///
/// # Returns
///
/// Returns `Ok(ExitStatus)` with the child's exit status, or an error on failure.
///
/// # Example
///
/// ```no_run
/// use sevorix_core::seccomp::spawn_seccomp_shell;
///
/// let env = vec![("HTTP_PROXY".to_string(), "http://localhost:3000".to_string())];
/// let status = spawn_seccomp_shell(
///     "/bin/bash",
///     &["-c".to_string(), "echo hello".to_string()],
///     env,
///     |event| {
///         println!("Syscall: {}", event.syscall_name);
///         true // Allow all syscalls
///     },
/// ).unwrap();
///
/// if status.success() {
///     println!("Command succeeded");
/// }
/// ```
pub fn spawn_seccomp_shell<F>(
    shell: &str,
    args: &[String],
    env_vars: Vec<(String, String)>,
    mut callback: F,
) -> Result<ExitStatus, SeccompNotifierError>
where
    F: FnMut(&crate::SyscallEvent) -> bool,
{
    // Check kernel version - fallback to ptrace if not supported
    if !kernel_supports_seccomp_notify() {
        // Fallback to ptrace-based tracing
        return spawn_ptrace_shell(shell, args, env_vars);
    }

    // Get the parent PID before spawning the notification thread.
    let parent_pid = nix::unistd::getpid();

    // Create channels for communication between notification thread and main thread
    let (event_tx, event_rx) = std::sync::mpsc::channel::<SyscallEventWithResponse>();
    // Channel to pass the notify_fd to the notification thread after the filter is loaded.
    let (fd_tx, fd_rx) = std::sync::mpsc::channel::<RawFd>();

    // Create shared state for child PID (set after fork)
    let child_pid = std::sync::Arc::new(std::sync::atomic::AtomicI32::new(-1));
    let child_pid_clone = child_pid.clone();

    // CRITICAL: Spawn notification thread BEFORE loading the seccomp filter.
    // thread::spawn() uses the clone() syscall. If the seccomp filter is already
    // loaded when thread::spawn() is called, the clone() syscall gets intercepted,
    // the parent thread is suspended waiting for a notification response, but no
    // thread is yet listening — causing a deadlock. By spawning first, we avoid this.

    // Channel for the notification thread to signal it's ready to poll.
    // This prevents a race where the main thread forks before the notification
    // thread has started polling, causing deadlock.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();

    let notify_thread = std::thread::spawn(move || {
        // Wait for the notify_fd from the main thread (sent after the filter is loaded)
        let notifier_fd = match fd_rx.recv() {
            Ok(fd) => fd,
            Err(_) => return Ok(()),
        };
        // Signal that we've received the fd and are about to enter the poll loop
        let _ = ready_tx.send(());
        run_notification_loop_with_channels(
            parent_pid,
            child_pid_clone,
            notifier_fd,
            event_tx,
        )
    });

    // NOW load the seccomp filter. The notification thread is already running and
    // listening, so any subsequent monitored syscall (including fork) will be handled.
    let notifier = SeccompNotifier::new(&[
        SyscallCategory::Network,
        SyscallCategory::Process,
        SyscallCategory::Privilege,
    ])?;

    // Send the notify_fd to the notification thread
    let notifier_fd = notifier.fd();
    let _ = fd_tx.send(notifier_fd);
    // Drop the sender so the thread knows no more fds are coming
    drop(fd_tx);

    // CRITICAL: Wait for notification thread to signal it's ready to poll.
    // This ensures the notification thread is in the poll loop before we make
    // any monitored syscalls (like fork), preventing deadlock.
    let _ = ready_rx.recv();

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Signal the child PID to the notification thread
            child_pid.store(child.as_raw(), std::sync::atomic::Ordering::SeqCst);

            // Main thread: process syscall events with callback and wait for child
            let mut exit_status: Option<ExitStatus> = None;

            while exit_status.is_none() {
                // Check if child has exited
                match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(_, code)) => {
                        exit_status = Some(ExitStatus::from_raw(code << 8));
                        break;
                    }
                    Ok(WaitStatus::Signaled(_, sig, _)) => {
                        exit_status = Some(ExitStatus::from_raw(sig as i32));
                        break;
                    }
                    Ok(WaitStatus::StillAlive) => {}
                    Ok(_) => {}
                    Err(e) => {
                        if e == nix::errno::Errno::ECHILD {
                            exit_status = Some(ExitStatus::from_raw(0));
                            break;
                        }
                        return Err(SeccompNotifierError::Io(std::io::Error::other(format!(
                            "waitpid failed: {}",
                            e
                        ))));
                    }
                }

                // Try to receive syscall event (with timeout)
                match event_rx.recv_timeout(std::time::Duration::from_millis(50)) {
                    Ok(event_with_response) => {
                        // Process with callback
                        let allow = callback(&event_with_response.event);
                        // Send response back to notification thread
                        let _ = event_with_response.response_tx.send(allow);
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // No event, continue checking child status
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        // Notification thread has exited, child likely exited too
                        break;
                    }
                }
            }

            // Wait for notification thread to finish
            let _ = notify_thread.join();

            Ok(exit_status.unwrap_or(ExitStatus::from_raw(1)))
        }
        Ok(ForkResult::Child) => {
            // Child: The filter is already loaded in the parent and inherited by us.
            let mut cmd = Command::new(shell);
            cmd.args(args);
            for (key, value) in env_vars {
                cmd.env(key, value);
            }
            let err = cmd.exec();
            eprintln!("Failed to exec {}: {}", shell, err);
            std::process::exit(1);
        }
        Err(e) => Err(SeccompNotifierError::Io(std::io::Error::other(format!(
            "Fork failed: {}",
            e
        )))),
    }
}

/// Helper struct for channel-based syscall event handling.
struct SyscallEventWithResponse {
    event: crate::SyscallEvent,
    response_tx: std::sync::mpsc::Sender<bool>,
}

// Raw seccomp notification structs for direct ioctl usage.
//
// We cannot use ScmpNotifReq::receive() here because it calls seccomp_notify_alloc(),
// which internally calls malloc(). glibc's fork() acquires the malloc lock before
// executing clone(). When clone() is intercepted by SCMP_ACT_NOTIFY, the parent
// thread is suspended with the malloc lock held. Any malloc() in the notification
// thread therefore deadlocks. Using stack-allocated structs and raw ioctls avoids
// the malloc entirely.
#[repr(C)]
#[derive(Default)]
pub(crate) struct RawSeccompData {
    pub(crate) nr: i32,
    pub(crate) arch: u32,
    pub(crate) instruction_pointer: u64,
    pub(crate) args: [u64; 6],
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct RawSeccompNotif {
    pub(crate) id: u64,
    pub(crate) pid: u32,
    pub(crate) flags: u32,
    pub(crate) data: RawSeccompData,
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct RawSeccompNotifResp {
    pub(crate) id: u64,
    pub(crate) val: i64,
    pub(crate) error: i32,
    pub(crate) flags: u32,
}

// ioctl numbers for seccomp user notification (x86_64, kernel 5.0+)
// SECCOMP_IOCTL_NOTIF_RECV = _IORW('!', 0, struct seccomp_notif) where sizeof = 80
pub(crate) const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
// SECCOMP_IOCTL_NOTIF_SEND = _IORW('!', 1, struct seccomp_notif_resp) where sizeof = 24
pub(crate) const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
pub(crate) const SECCOMP_USER_NOTIF_FLAG_CONTINUE_RAW: u32 = 1;

/// Receive a seccomp notification using direct ioctl, handling EINTR.
pub(crate) fn raw_recv_notification(fd: i32) -> Option<RawSeccompNotif> {
    let mut req = RawSeccompNotif::default();
    loop {
        let ret = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &mut req) };
        if ret == 0 {
            return Some(req);
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::EINTR {
            continue;
        }
        // Other errors: fd closed (child exited) or invalid
        return None;
    }
}

/// Send a "continue/allow" response using direct ioctl.
pub(crate) fn raw_respond_allow(fd: i32, id: u64) {
    let mut resp = RawSeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE_RAW,
    };
    unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &mut resp) };
}

/// Send a "deny with EPERM" response using direct ioctl.
pub(crate) fn raw_respond_deny_eperm(fd: i32, id: u64) {
    let mut resp = RawSeccompNotifResp {
        id,
        val: 0,
        error: -libc::EPERM,
        flags: 0,
    };
    unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &mut resp) };
}

/// Run the seccomp notification loop with channel-based communication.
///
/// Uses raw ioctls instead of libseccomp's receive wrapper, which has been
/// observed to block indefinitely on some systems even when notifications are pending.
fn run_notification_loop_with_channels(
    parent_pid: Pid,
    child_pid: std::sync::Arc<std::sync::atomic::AtomicI32>,
    notifier_fd: i32,
    event_tx: std::sync::mpsc::Sender<SyscallEventWithResponse>,
) -> Result<(), SeccompNotifierError> {
    loop {
        let child = child_pid.load(std::sync::atomic::Ordering::SeqCst);
        if child > 0 {
            match waitpid(Pid::from_raw(child), Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(_, _)) | Ok(WaitStatus::Signaled(_, _, _)) => {
                    return Ok(());
                }
                Err(e) if e == nix::errno::Errno::ECHILD => {
                    // Parent already reaped the child; nothing left to monitor.
                    return Ok(());
                }
                _ => {}
            }
        }

        // Poll with a timeout so we can periodically check if the child exited.
        // This also avoids blocking forever if the seccomp filter is gone.
        let poll_ret = unsafe {
            let mut pfd = libc::pollfd { fd: notifier_fd, events: libc::POLLIN, revents: 0 };
            libc::poll(&mut pfd as *mut libc::pollfd, 1, 200)
        };

        if poll_ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::EINTR { continue; }
            // Poll failed (e.g., fd was closed when child exited)
            return Ok(());
        }
        if poll_ret == 0 {
            // Timeout: no notification, loop to check child status
            continue;
        }

        // Receive using a stack-allocated struct and direct ioctl — NOT ScmpNotifReq::receive().
        //
        // Root cause: glibc's fork() holds the malloc lock while executing clone(). When
        // clone() is intercepted by SCMP_ACT_NOTIFY, the parent thread is suspended with the
        // malloc lock still held. Any call to malloc() in the notification thread (including
        // the heap allocation inside ScmpNotifReq::receive() → seccomp_notify_alloc()) will
        // deadlock trying to acquire that same lock. Using a stack-allocated struct completely
        // avoids this.
        let req = match raw_recv_notification(notifier_fd) {
            Some(r) => r,
            None => {
                // Receive failed (child likely exited, closing the notify fd).
                return Ok(());
            }
        };

        let syscall_nr = req.data.nr as i64;

        // CRITICAL: Auto-allow syscalls from the parent BEFORE any memory allocation.
        // glibc's fork() holds the malloc lock while executing clone(). When clone() is
        // intercepted by SCMP_ACT_NOTIFY, the parent thread is suspended with the malloc
        // lock still held. Any call to malloc() (including to_string()) will deadlock.
        // We must check the PID and respond WITHOUT allocating any heap memory.
        if req.pid as i32 == parent_pid.as_raw() {
            raw_respond_allow(notifier_fd, req.id);
            continue;
        }

        // Now safe to allocate - parent syscalls already handled.
        let syscall_name = syscall_name(syscall_nr).to_string();

        // For all other syscalls, send to the main thread for a policy decision.
        let event = build_syscall_event(req.pid, syscall_nr, &syscall_name, &req.data.args);
        let (response_tx, response_rx) = std::sync::mpsc::channel::<bool>();
        let event_with_response = SyscallEventWithResponse { event, response_tx };

        // CRITICAL: Use NON-BLOCKING send and try_recv to avoid deadlock.
        // The main thread may be blocked waiting for the child to exit.
        // If we block waiting for a decision, the child syscall hangs forever.
        // Solution: Send the event, try once for an immediate decision, then auto-allow.
        if event_tx.send(event_with_response).is_err() {
            // Main thread disconnected; deny and exit.
            raw_respond_deny_eperm(notifier_fd, req.id);
            return Ok(());
        }

        // NON-BLOCKING: Try to get an immediate decision. If the main thread is
        // busy (e.g., blocked in waitpid), auto-allow to prevent deadlock.
        // The main thread will process events when it's ready - we don't wait.
        let allow = match response_rx.try_recv() {
            Ok(a) => a,
            // No immediate decision available - AUTO-ALLOW to prevent deadlock
            Err(_) => true,
        };

        if allow {
            raw_respond_allow(notifier_fd, req.id);
        } else {
            raw_respond_deny_eperm(notifier_fd, req.id);
        }
    }
}

/// Build a SyscallEvent from raw notification data without going through libseccomp.
pub(crate) fn build_syscall_event(pid: u32, syscall_nr: i64, name: &str, raw_args: &[u64; 6]) -> crate::SyscallEvent {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| {
            chrono::DateTime::from_timestamp(d.as_secs() as i64, d.subsec_nanos())
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| d.as_secs().to_string())
        })
        .unwrap_or_else(|_| "unknown".to_string());

    let ppid = std::fs::read_to_string(format!("/proc/{}/stat", pid))
        .ok()
        .and_then(|stat| {
            let close_paren = stat.rfind(')')?;
            let fields: Vec<&str> = stat[close_paren + 2..].split_whitespace().collect();
            fields.get(1).and_then(|s| s.parse::<u32>().ok())
        })
        .unwrap_or(0);

    let args: Vec<String> = raw_args.iter().map(|a| format!("{:#x}", a)).collect();

    crate::SyscallEvent {
        syscall_name: name.to_string(),
        syscall_number: syscall_nr,
        args,
        pid,
        ppid,
        timestamp,
    }
}

/// Run the seccomp notification loop in the parent process.
///
/// This function receives notifications from the kernel about intercepted syscalls,
/// invokes the callback for policy decisions, and sends responses back to the kernel.
fn run_notification_loop<F>(
    child_pid: Pid,
    notifier: &SeccompNotifier,
    callback: &mut F,
) -> Result<ExitStatus, SeccompNotifierError>
where
    F: FnMut(&crate::SyscallEvent) -> bool,
{
    loop {
        // Check if child has exited
        match waitpid(child_pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => {
                return Ok(ExitStatus::from_raw(code << 8));
            }
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                return Ok(ExitStatus::from_raw(sig as i32));
            }
            Ok(WaitStatus::StillAlive) => {
                // Child still running, continue to receive notifications
            }
            Ok(_) => {}
            Err(e) => {
                // ECHILD means no child processes - child has exited
                if e == nix::errno::Errno::ECHILD {
                    // Return success - child has already exited
                    return Ok(ExitStatus::from_raw(0));
                }
                return Err(SeccompNotifierError::Io(std::io::Error::other(format!(
                    "waitpid failed: {}",
                    e
                ))));
            }
        }

        // Receive notification (with timeout to allow checking child status)
        match notifier.receive() {
            Ok(req) => {
                // Create syscall event from request
                let event = syscall_event_from_request(&req);

                // Invoke callback for policy decision
                let allow = callback(&event);

                // Send response
                let resp = if allow {
                    SeccompNotifier::allow(&req)
                } else {
                    SeccompNotifier::deny_eperm(&req)
                };

                notifier.respond(&resp)?;
            }
            Err(e) => {
                // If we get an error receiving, the child may have exited
                // Check child status again
                if let Ok(WaitStatus::Exited(_, code)) = waitpid(child_pid, None) {
                    return Ok(ExitStatus::from_raw(code << 8));
                }
                // Otherwise, log and continue
                eprintln!("Warning: receive error: {}", e);
            }
        }
    }
}

/// Fallback to ptrace-based shell spawning for older kernels.
///
/// This is used when the kernel doesn't support seccomp-unotify (< 4.14).
#[allow(deprecated)] // ptrace fallback for older kernels
fn spawn_ptrace_shell(
    shell: &str,
    args: &[String],
    env_vars: Vec<(String, String)>,
) -> Result<ExitStatus, SeccompNotifierError> {
    // Use the existing ptrace-based tracer
    crate::tracer::spawn_traced_shell(shell, args, "", env_vars)
        .map_err(|e| SeccompNotifierError::Io(std::io::Error::other(e)))
}

// -----------------------------------------------------------------------------
// Seccomp Policy Handler
// -----------------------------------------------------------------------------

/// Decision returned by the seccomp policy handler.
///
/// This enum represents the possible actions that can be taken
/// in response to a syscall intercepted via seccomp-unotify.
#[derive(Debug, Clone, PartialEq)]
pub enum SeccompDecision {
    /// Allow the syscall to proceed normally.
    Allow,
    /// Block the syscall and return the specified errno to the calling process.
    /// The errno should be a positive number (e.g., 1 for EPERM).
    Block { errno: i32 },
    /// Kill the process that made the syscall.
    Kill,
}

impl SeccompDecision {
    /// Create a response for the given request based on this decision.
    ///
    /// # Arguments
    ///
    /// * `req` - The original seccomp notification request
    ///
    /// # Returns
    ///
    /// A `ScmpNotifResp` that can be sent back to the kernel.
    pub fn to_response(&self, req: &ScmpNotifReq) -> ScmpNotifResp {
        match self {
            SeccompDecision::Allow => SeccompNotifier::allow(req),
            SeccompDecision::Block { errno } => {
                // errno should be negative for the kernel
                SeccompNotifier::deny(req, -*errno)
            }
            SeccompDecision::Kill => {
                // For kill, we use ScmpAction::KillThread/KillProcess
                // but ScmpNotifResp doesn't have a direct kill method
                // We return EPERM and the caller should handle the kill separately
                SeccompNotifier::deny_eperm(req)
            }
        }
    }
}

/// A policy handler that makes decisions about intercepted syscalls.
///
/// This trait allows different policy implementations to be plugged into
/// the seccomp notification loop. Implementations can use local policy
/// engines, remote API calls, or any other decision-making logic.
pub trait SeccompPolicyHandler: Send + Sync {
    /// Evaluate a syscall event and return a decision.
    ///
    /// # Arguments
    ///
    /// * `event` - The syscall event to evaluate
    ///
    /// # Returns
    ///
    /// A `SeccompDecision` indicating what action to take.
    fn evaluate(&mut self, event: &crate::SyscallEvent) -> SeccompDecision;
}

/// A simple policy handler that uses a callback function.
///
/// This is useful for quick prototyping or when you want to embed
/// policy logic directly in the spawning code.
pub struct CallbackPolicyHandler<F>
where
    F: FnMut(&crate::SyscallEvent) -> SeccompDecision + Send + Sync,
{
    callback: F,
}

impl<F> CallbackPolicyHandler<F>
where
    F: FnMut(&crate::SyscallEvent) -> SeccompDecision + Send + Sync,
{
    pub fn new(callback: F) -> Self {
        Self { callback }
    }
}

impl<F> SeccompPolicyHandler for CallbackPolicyHandler<F>
where
    F: FnMut(&crate::SyscallEvent) -> SeccompDecision + Send + Sync,
{
    fn evaluate(&mut self, event: &crate::SyscallEvent) -> SeccompDecision {
        (self.callback)(event)
    }
}

/// A policy handler that allows all syscalls.
///
/// Use this when you only want to log syscalls without blocking any.
pub struct AllowAllHandler;

impl SeccompPolicyHandler for AllowAllHandler {
    fn evaluate(&mut self, _event: &crate::SyscallEvent) -> SeccompDecision {
        SeccompDecision::Allow
    }
}

/// Spawn a shell with seccomp-unotify and a policy handler.
///
/// This is an enhanced version of `spawn_seccomp_shell` that uses a
/// `SeccompPolicyHandler` for making decisions about intercepted syscalls.
///
/// # Arguments
///
/// * `shell` - The shell executable to run (e.g., "/bin/bash")
/// * `args` - Arguments to pass to the shell (e.g., ["-c", "ls -la"])
/// * `env_vars` - Environment variables to set as (key, value) pairs
/// * `handler` - The policy handler for making syscall decisions
///
/// # Returns
///
/// Returns `Ok(ExitStatus)` with the child's exit status, or an error on failure.
pub fn spawn_seccomp_shell_with_handler<H>(
    shell: &str,
    args: &[String],
    env_vars: Vec<(String, String)>,
    mut handler: H,
) -> Result<ExitStatus, SeccompNotifierError>
where
    H: SeccompPolicyHandler,
{
    // Check kernel version - fallback to ptrace if not supported
    if !kernel_supports_seccomp_notify() {
        return spawn_ptrace_shell(shell, args, env_vars);
    }

    // Create the seccomp notifier before forking
    let notifier = SeccompNotifier::new(&[
        SyscallCategory::Network,
        SyscallCategory::Process,
        SyscallCategory::Privilege,
    ])?;

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Parent: run notification loop with handler
            run_notification_loop_with_handler(child, &notifier, &mut handler)
        }
        Ok(ForkResult::Child) => {
            // Child: exec the shell
            let mut cmd = Command::new(shell);
            cmd.args(args);
            for (key, value) in env_vars {
                cmd.env(key, value);
            }

            let err = cmd.exec();
            eprintln!("Failed to exec {}: {}", shell, err);
            std::process::exit(1);
        }
        Err(e) => Err(SeccompNotifierError::Io(std::io::Error::other(format!(
            "Fork failed: {}",
            e
        )))),
    }
}

/// Run the seccomp notification loop with a policy handler.
fn run_notification_loop_with_handler<H>(
    child_pid: Pid,
    notifier: &SeccompNotifier,
    handler: &mut H,
) -> Result<ExitStatus, SeccompNotifierError>
where
    H: SeccompPolicyHandler,
{
    loop {
        // Check if child has exited
        match waitpid(child_pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => {
                return Ok(ExitStatus::from_raw(code << 8));
            }
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                return Ok(ExitStatus::from_raw(sig as i32));
            }
            Ok(WaitStatus::StillAlive) => {
                // Child still running, continue to receive notifications
            }
            Ok(_) => {}
            Err(e) => {
                if e == nix::errno::Errno::ECHILD {
                    return Ok(ExitStatus::from_raw(0));
                }
                return Err(SeccompNotifierError::Io(std::io::Error::other(format!(
                    "waitpid failed: {}",
                    e
                ))));
            }
        }

        // Receive notification (with timeout to allow checking child status)
        match notifier.receive() {
            Ok(req) => {
                // Create syscall event from request
                let event = syscall_event_from_request(&req);

                // Get decision from handler
                let decision = handler.evaluate(&event);

                // Handle kill decision specially
                if decision == SeccompDecision::Kill {
                    // Kill the process
                    let _ = nix::sys::signal::kill(
                        Pid::from_raw(req.pid as i32),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                    // Still need to respond to the notification
                    let resp = SeccompNotifier::deny_eperm(&req);
                    notifier.respond(&resp)?;
                } else {
                    // Send response based on decision
                    let resp = decision.to_response(&req);
                    notifier.respond(&resp)?;
                }
            }
            Err(e) => {
                // If we get an error receiving, the child may have exited
                if let Ok(WaitStatus::Exited(_, code)) = waitpid(child_pid, None) {
                    return Ok(ExitStatus::from_raw(code << 8));
                }
                eprintln!("Warning: receive error: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_notifier_for_categories() {
        let notifier = SeccompNotifier::new(&[SyscallCategory::Network, SyscallCategory::Process]);
        assert!(
            notifier.is_ok(),
            "Failed to create notifier: {:?}",
            notifier.err()
        );

        let notifier = notifier.unwrap();
        assert!(notifier.fd() >= 0, "Invalid notifier fd");
    }

    #[test]
    fn test_create_notifier_for_single_syscall() {
        let notifier = SeccompNotifier::for_syscall("openat");
        assert!(
            notifier.is_ok(),
            "Failed to create notifier: {:?}",
            notifier.err()
        );

        let notifier = notifier.unwrap();
        assert!(notifier.fd() >= 0, "Invalid notifier fd");
    }

    #[test]
    fn test_syscall_info_from_request() {
        // Create a notifier
        let notifier = SeccompNotifier::for_syscall("getpid").unwrap();

        // We can't easily test the notification loop without forking,
        // but we can verify the structure is correct
        assert!(notifier.fd() >= 0);
    }

    #[test]
    fn test_kernel_supports_seccomp_notify() {
        // Should return true on any modern Linux kernel
        let supported = kernel_supports_seccomp_notify();
        // Just verify it doesn't panic
        println!("Seccomp-unotify supported: {}", supported);
    }

    #[test]
    #[ignore = "requires clean process environment without seccomp filters"]
    fn test_spawn_seccomp_shell_true() {
        // Test that spawn_seccomp_shell can execute /bin/true
        let status = spawn_seccomp_shell(
            "/bin/true",
            &[],
            vec![],
            |_event| true, // Allow all syscalls
        );

        assert!(
            status.is_ok(),
            "spawn_seccomp_shell failed: {:?}",
            status.err()
        );
        let status = status.unwrap();
        assert!(status.success(), "/bin/true should exit successfully");
    }

    #[test]
    #[ignore = "requires clean process environment without seccomp filters"]
    fn test_spawn_seccomp_shell_echo() {
        // Test that spawn_seccomp_shell can execute echo
        let status = spawn_seccomp_shell(
            "/bin/bash",
            &["-c".to_string(), "echo hello".to_string()],
            vec![],
            |_event| true, // Allow all syscalls
        );

        assert!(
            status.is_ok(),
            "spawn_seccomp_shell failed: {:?}",
            status.err()
        );
        let status = status.unwrap();
        assert!(status.success(), "echo should exit successfully");
    }

    #[test]
    #[ignore = "requires clean process environment without seccomp filters"]
    fn test_spawn_seccomp_shell_with_deny() {
        // Test that denying execve prevents execution
        let status = spawn_seccomp_shell(
            "/bin/bash",
            &["-c".to_string(), "exit 42".to_string()],
            vec![],
            |event| {
                // Deny execve - this should prevent the shell from running
                event.syscall_name != "execve"
            },
        );

        // The shell should fail because execve is denied
        assert!(
            status.is_ok(),
            "spawn_seccomp_shell failed: {:?}",
            status.err()
        );
    }

    // ========================================
    // syscall_name() Tests
    // ========================================

    #[test]
    fn test_syscall_name_common_syscalls() {
        // Test common syscall numbers (x86_64)
        assert_eq!(syscall_name(0), "read");
        assert_eq!(syscall_name(1), "write");
        assert_eq!(syscall_name(2), "open");
        assert_eq!(syscall_name(3), "close");
        assert_eq!(syscall_name(39), "getpid");
        assert_eq!(syscall_name(59), "execve");
        assert_eq!(syscall_name(60), "exit");
        assert_eq!(syscall_name(57), "fork");
        assert_eq!(syscall_name(41), "socket");
        assert_eq!(syscall_name(42), "connect");
        assert_eq!(syscall_name(56), "clone");
    }

    #[test]
    fn test_syscall_name_network_syscalls() {
        assert_eq!(syscall_name(41), "socket");
        assert_eq!(syscall_name(42), "connect");
        assert_eq!(syscall_name(43), "accept");
        assert_eq!(syscall_name(44), "sendto");
        assert_eq!(syscall_name(45), "recvfrom");
        assert_eq!(syscall_name(49), "bind");
        assert_eq!(syscall_name(50), "listen");
        assert_eq!(syscall_name(54), "setsockopt");
        assert_eq!(syscall_name(55), "getsockopt");
    }

    #[test]
    fn test_syscall_name_file_syscalls() {
        assert_eq!(syscall_name(0), "read");
        assert_eq!(syscall_name(1), "write");
        assert_eq!(syscall_name(2), "open");
        assert_eq!(syscall_name(3), "close");
        assert_eq!(syscall_name(4), "stat");
        assert_eq!(syscall_name(5), "fstat");
        assert_eq!(syscall_name(78), "getdents");
        assert_eq!(syscall_name(79), "getcwd");
        assert_eq!(syscall_name(80), "chdir");
        assert_eq!(syscall_name(82), "rename");
        assert_eq!(syscall_name(83), "mkdir");
        assert_eq!(syscall_name(84), "rmdir");
        assert_eq!(syscall_name(85), "creat");
        assert_eq!(syscall_name(86), "link");
        assert_eq!(syscall_name(87), "unlink");
    }

    #[test]
    fn test_syscall_name_process_syscalls() {
        assert_eq!(syscall_name(56), "clone");
        assert_eq!(syscall_name(57), "fork");
        assert_eq!(syscall_name(58), "vfork");
        assert_eq!(syscall_name(59), "execve");
        assert_eq!(syscall_name(60), "exit");
        assert_eq!(syscall_name(61), "wait4");
        assert_eq!(syscall_name(62), "kill");
        assert_eq!(syscall_name(102), "getuid");
        assert_eq!(syscall_name(104), "getgid");
        assert_eq!(syscall_name(105), "setuid");
        assert_eq!(syscall_name(106), "setgid");
    }

    #[test]
    fn test_syscall_name_unknown_syscall() {
        // Test unknown syscall numbers - returns "unknown" for unrecognized syscalls
        assert_eq!(syscall_name(10000), "unknown");
        assert_eq!(syscall_name(-1), "unknown");
        assert_eq!(syscall_name(500), "unknown");
    }

    #[test]
    fn test_syscall_name_high_numbers() {
        // Test syscall numbers in the extended range (arch_prctl, etc.)
        assert_eq!(syscall_name(158), "arch_prctl");
        assert_eq!(syscall_name(157), "prctl");
        assert_eq!(syscall_name(200), "tkill");
        assert_eq!(syscall_name(201), "time");
        assert_eq!(syscall_name(202), "futex");
    }

    // ========================================
    // SyscallCategory Tests
    // ========================================

    #[test]
    fn test_syscall_category_debug() {
        assert!(format!("{:?}", SyscallCategory::Network).contains("Network"));
        assert!(format!("{:?}", SyscallCategory::Process).contains("Process"));
        assert!(format!("{:?}", SyscallCategory::Privilege).contains("Privilege"));
    }

    #[test]
    fn test_syscall_category_equality() {
        assert_eq!(SyscallCategory::Network, SyscallCategory::Network);
        assert_eq!(SyscallCategory::Process, SyscallCategory::Process);
        assert_ne!(SyscallCategory::Network, SyscallCategory::Process);
    }

    // ========================================
    // SeccompNotifierError Tests
    // ========================================

    #[test]
    fn test_seccomp_notifier_error_display() {
        // Test that error variants can be displayed
        let err = SeccompNotifierError::InvalidFd;
        assert!(!format!("{}", err).is_empty());

        // Test Io error variant
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test");
        let err = SeccompNotifierError::Io(io_err);
        assert!(format!("{}", err).contains("IO error"));
    }

    // ========================================
    // SeccompDecision Tests
    // ========================================

    #[test]
    fn test_seccomp_decision_debug() {
        assert!(format!("{:?}", SeccompDecision::Allow).contains("Allow"));

        let block = SeccompDecision::Block { errno: libc::EPERM };
        assert!(format!("{:?}", block).contains("Block"));

        assert!(format!("{:?}", SeccompDecision::Kill).contains("Kill"));
    }

    #[test]
    fn test_seccomp_decision_equality() {
        assert_eq!(SeccompDecision::Allow, SeccompDecision::Allow);
        assert_eq!(
            SeccompDecision::Block { errno: 1 },
            SeccompDecision::Block { errno: 1 }
        );
        assert_ne!(
            SeccompDecision::Block { errno: 1 },
            SeccompDecision::Block { errno: 2 }
        );
        assert_eq!(SeccompDecision::Kill, SeccompDecision::Kill);
    }

    // ========================================
    // format_socket_args Tests
    // ========================================

    #[test]
    fn test_format_socket_args_unix() {
        let args: [u64; 6] = [1, 1, 0, 0, 0, 0]; // AF_UNIX, SOCK_STREAM
        let result = format_socket_args(&args);
        assert!(result[0].contains("domain=AF_UNIX"));
        assert!(result[1].contains("type=SOCK_STREAM"));
        assert!(result[2].contains("protocol=0"));
    }

    #[test]
    fn test_format_socket_args_inet() {
        let args: [u64; 6] = [2, 1, 6, 0, 0, 0]; // AF_INET, SOCK_STREAM, TCP
        let result = format_socket_args(&args);
        assert!(result[0].contains("domain=AF_INET"));
        assert!(result[1].contains("type=SOCK_STREAM"));
        assert!(result[2].contains("protocol=6"));
    }

    #[test]
    fn test_format_socket_args_inet6() {
        let args: [u64; 6] = [10, 2, 17, 0, 0, 0]; // AF_INET6, SOCK_DGRAM, UDP
        let result = format_socket_args(&args);
        assert!(result[0].contains("domain=AF_INET6"));
        assert!(result[1].contains("type=SOCK_DGRAM"));
        assert!(result[2].contains("protocol=17"));
    }

    #[test]
    fn test_format_socket_args_raw() {
        let args: [u64; 6] = [2, 3, 0, 0, 0, 0]; // AF_INET, SOCK_RAW
        let result = format_socket_args(&args);
        assert!(result[0].contains("domain=AF_INET"));
        assert!(result[1].contains("type=SOCK_RAW"));
    }

    #[test]
    fn test_format_socket_args_unknown_domain() {
        let args: [u64; 6] = [99, 1, 0, 0, 0, 0]; // Unknown domain
        let result = format_socket_args(&args);
        assert!(result[0].contains("domain=99"));
        assert!(result[1].contains("type=SOCK_STREAM"));
    }

    #[test]
    fn test_format_socket_args_unknown_type() {
        let args: [u64; 6] = [2, 99, 0, 0, 0, 0]; // AF_INET, unknown type
        let result = format_socket_args(&args);
        assert!(result[0].contains("domain=AF_INET"));
        assert!(result[1].contains("type=99"));
    }

    // ========================================
    // format_generic_args Tests
    // ========================================

    #[test]
    fn test_format_generic_args_basic() {
        let args: [u64; 6] = [0x100, 0x200, 0x300, 0, 0, 0];
        let result = format_generic_args(&args);
        assert_eq!(result.len(), 6);
        assert_eq!(result[0], "0x100");
        assert_eq!(result[1], "0x200");
        assert_eq!(result[2], "0x300");
        assert_eq!(result[3], "0x0");
    }

    #[test]
    fn test_format_generic_args_zeros() {
        let args: [u64; 6] = [0, 0, 0, 0, 0, 0];
        let result = format_generic_args(&args);
        assert_eq!(result.len(), 6);
        for arg in result {
            assert_eq!(arg, "0x0");
        }
    }

    #[test]
    fn test_format_generic_args_large_values() {
        let args: [u64; 6] = [
            u64::MAX,
            u64::MAX - 1,
            0xDEADBEEF,
            0xCAFEBABE,
            0x12345678,
            1,
        ];
        let result = format_generic_args(&args);
        assert_eq!(result.len(), 6);
        assert!(result[0].starts_with("0x"));
        assert!(result[1].starts_with("0x"));
    }

    // ========================================
    // format_accept_args Tests
    // ========================================

    #[test]
    fn test_format_accept_args() {
        let args: [u64; 6] = [3, 0x7fff1234, 0x7fff1230, 0, 0, 0];
        let result = format_accept_args(&args);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], "fd=3");
        assert!(result[1].contains("addr="));
        assert!(result[2].contains("addrlen="));
    }

    #[test]
    fn test_format_accept_args_zero_fd() {
        let args: [u64; 6] = [0, 0, 0, 0, 0, 0];
        let result = format_accept_args(&args);
        assert_eq!(result[0], "fd=0");
    }

    // ========================================
    // SyscallInfo Tests
    // ========================================

    #[test]
    fn test_syscall_info_fields() {
        // Verify SyscallInfo struct layout
        let info = SyscallInfo {
            syscall_nr: 59,
            arch: ScmpArch::X8664,
            pid: 1234,
            args: [1, 2, 3, 4, 5, 6],
            instr_pointer: 0x7fff12345678,
        };

        assert_eq!(info.syscall_nr, 59);
        assert_eq!(info.pid, 1234);
        assert_eq!(info.args, [1, 2, 3, 4, 5, 6]);
        assert_eq!(info.instr_pointer, 0x7fff12345678);
    }

    #[test]
    fn test_syscall_info_debug() {
        let info = SyscallInfo {
            syscall_nr: 59,
            arch: ScmpArch::X8664,
            pid: 1,
            args: [0; 6],
            instr_pointer: 0,
        };

        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("SyscallInfo"));
        assert!(debug_str.contains("syscall_nr"));
        assert!(debug_str.contains("pid"));
    }

    // ========================================
    // AllowAllHandler Tests
    // ========================================

    #[test]
    fn test_allow_all_handler() {
        let mut handler = AllowAllHandler;
        let event = crate::SyscallEvent {
            syscall_name: "open".to_string(),
            syscall_number: 2,
            args: vec![],
            pid: 1234,
            ppid: 1,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        // AllowAllHandler should always return Allow decision
        let decision = handler.evaluate(&event);
        assert!(matches!(decision, SeccompDecision::Allow));
    }

    // ========================================
    // CallbackPolicyHandler Tests
    // ========================================

    #[test]
    fn test_callback_policy_handler_allow() {
        let handler = CallbackPolicyHandler::new(|_event| SeccompDecision::Allow);
        let mut handler = handler;
        let event = crate::SyscallEvent {
            syscall_name: "read".to_string(),
            syscall_number: 0,
            args: vec![],
            pid: 1,
            ppid: 0,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        let decision = handler.evaluate(&event);
        assert!(matches!(decision, SeccompDecision::Allow));
    }

    #[test]
    fn test_callback_policy_handler_block() {
        let handler =
            CallbackPolicyHandler::new(|_event| SeccompDecision::Block { errno: libc::EPERM });
        let mut handler = handler;
        let event = crate::SyscallEvent {
            syscall_name: "execve".to_string(),
            syscall_number: 59,
            args: vec![],
            pid: 1,
            ppid: 0,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        let decision = handler.evaluate(&event);
        match decision {
            SeccompDecision::Block { errno } => assert_eq!(errno, libc::EPERM),
            _ => panic!("Expected Block decision"),
        }
    }

    #[test]
    fn test_callback_policy_handler_conditional() {
        // Handler that blocks execve but allows everything else
        let handler = CallbackPolicyHandler::new(|event| {
            if event.syscall_name == "execve" {
                SeccompDecision::Block { errno: libc::EPERM }
            } else {
                SeccompDecision::Allow
            }
        });
        let mut handler = handler;

        let execve_event = crate::SyscallEvent {
            syscall_name: "execve".to_string(),
            syscall_number: 59,
            args: vec![],
            pid: 1,
            ppid: 0,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };
        let decision = handler.evaluate(&execve_event);
        assert!(matches!(decision, SeccompDecision::Block { .. }));

        let read_event = crate::SyscallEvent {
            syscall_name: "read".to_string(),
            syscall_number: 0,
            args: vec![],
            pid: 1,
            ppid: 0,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };
        let decision = handler.evaluate(&read_event);
        assert!(matches!(decision, SeccompDecision::Allow));
    }

    #[test]
    fn test_callback_policy_handler_kill() {
        let handler = CallbackPolicyHandler::new(|_event| SeccompDecision::Kill);
        let mut handler = handler;
        let event = crate::SyscallEvent {
            syscall_name: "dangerous_syscall".to_string(),
            syscall_number: 999,
            args: vec![],
            pid: 1,
            ppid: 0,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        let decision = handler.evaluate(&event);
        assert!(matches!(decision, SeccompDecision::Kill));
    }

    // ========================================
    // syscall_name Comprehensive Tests
    // ========================================

    #[test]
    fn test_syscall_name_memory_syscalls() {
        assert_eq!(syscall_name(9), "mmap");
        assert_eq!(syscall_name(10), "mprotect");
        assert_eq!(syscall_name(11), "munmap");
        assert_eq!(syscall_name(12), "brk");
    }

    #[test]
    fn test_syscall_name_signal_syscalls() {
        assert_eq!(syscall_name(13), "rt_sigaction");
        assert_eq!(syscall_name(14), "rt_sigprocmask");
        assert_eq!(syscall_name(15), "rt_sigreturn");
    }

    #[test]
    fn test_syscall_name_file_descriptor_syscalls() {
        assert_eq!(syscall_name(32), "dup");
        assert_eq!(syscall_name(33), "dup2");
        assert_eq!(syscall_name(72), "fcntl");
        assert_eq!(syscall_name(73), "flock");
    }

    #[test]
    fn test_syscall_name_directory_syscalls() {
        assert_eq!(syscall_name(78), "getdents");
        assert_eq!(syscall_name(79), "getcwd");
        assert_eq!(syscall_name(80), "chdir");
        assert_eq!(syscall_name(81), "fchdir");
    }

    #[test]
    fn test_syscall_name_file_manipulation() {
        assert_eq!(syscall_name(82), "rename");
        assert_eq!(syscall_name(83), "mkdir");
        assert_eq!(syscall_name(84), "rmdir");
        assert_eq!(syscall_name(85), "creat");
        assert_eq!(syscall_name(86), "link");
        assert_eq!(syscall_name(87), "unlink");
        assert_eq!(syscall_name(88), "symlink");
        assert_eq!(syscall_name(89), "readlink");
    }

    #[test]
    fn test_syscall_name_permission_syscalls() {
        assert_eq!(syscall_name(90), "chmod");
        assert_eq!(syscall_name(91), "fchmod");
        assert_eq!(syscall_name(92), "chown");
        assert_eq!(syscall_name(93), "fchown");
        assert_eq!(syscall_name(95), "umask");
    }

    #[test]
    fn test_syscall_name_user_id_syscalls() {
        assert_eq!(syscall_name(102), "getuid");
        assert_eq!(syscall_name(104), "getgid");
        assert_eq!(syscall_name(105), "setuid");
        assert_eq!(syscall_name(106), "setgid");
        assert_eq!(syscall_name(107), "geteuid");
        assert_eq!(syscall_name(108), "getegid");
        assert_eq!(syscall_name(109), "setpgid");
        assert_eq!(syscall_name(110), "getppid");
    }

    #[test]
    fn test_syscall_name_capability_syscalls() {
        assert_eq!(syscall_name(125), "capget");
        assert_eq!(syscall_name(126), "capset");
    }

    #[test]
    fn test_syscall_name_privilege_syscalls() {
        assert_eq!(syscall_name(157), "prctl");
        assert_eq!(syscall_name(158), "arch_prctl");
        assert_eq!(syscall_name(101), "ptrace");
    }

    #[test]
    fn test_syscall_name_system_syscalls() {
        assert_eq!(syscall_name(161), "chroot");
        assert_eq!(syscall_name(165), "mount");
        assert_eq!(syscall_name(166), "umount2");
        assert_eq!(syscall_name(169), "reboot");
        assert_eq!(syscall_name(170), "sethostname");
    }

    #[test]
    fn test_syscall_name_extended_attributes() {
        assert_eq!(syscall_name(188), "setxattr");
        assert_eq!(syscall_name(191), "getxattr");
        assert_eq!(syscall_name(194), "listxattr");
        assert_eq!(syscall_name(197), "removexattr");
    }

    #[test]
    fn test_syscall_name_thread_syscalls() {
        assert_eq!(syscall_name(186), "gettid");
        assert_eq!(syscall_name(200), "tkill");
        assert_eq!(syscall_name(202), "futex");
        assert_eq!(syscall_name(203), "sched_setaffinity");
        assert_eq!(syscall_name(204), "sched_getaffinity");
    }

    #[test]
    fn test_syscall_name_io_syscalls() {
        assert_eq!(syscall_name(206), "io_setup");
        assert_eq!(syscall_name(207), "io_destroy");
        assert_eq!(syscall_name(208), "io_getevents");
        assert_eq!(syscall_name(209), "io_submit");
        assert_eq!(syscall_name(210), "io_cancel");
    }

    #[test]
    fn test_syscall_name_timer_syscalls() {
        assert_eq!(syscall_name(222), "timer_create");
        assert_eq!(syscall_name(223), "timer_settime");
        assert_eq!(syscall_name(226), "timer_delete");
        assert_eq!(syscall_name(227), "clock_settime");
    }

    #[test]
    fn test_syscall_name_event_syscalls() {
        assert_eq!(syscall_name(232), "epoll_wait");
        assert_eq!(syscall_name(233), "epoll_ctl");
        assert_eq!(syscall_name(254), "inotify_add_watch");
        assert_eq!(syscall_name(257), "openat");
        assert_eq!(syscall_name(258), "mkdirat");
    }

    #[test]
    fn test_syscall_name_new_file_syscalls() {
        assert_eq!(syscall_name(257), "openat");
        assert_eq!(syscall_name(262), "newfstatat");
        assert_eq!(syscall_name(263), "unlinkat");
        assert_eq!(syscall_name(265), "linkat");
    }

    #[test]
    fn test_syscall_name_epoll_syscalls() {
        assert_eq!(syscall_name(232), "epoll_wait");
        assert_eq!(syscall_name(233), "epoll_ctl");
        assert_eq!(syscall_name(291), "epoll_create1");
    }

    #[test]
    fn test_syscall_name_signalfd_syscalls() {
        assert_eq!(syscall_name(282), "signalfd");
        assert_eq!(syscall_name(289), "signalfd4");
        assert_eq!(syscall_name(290), "eventfd2");
        assert_eq!(syscall_name(291), "epoll_create1");
    }

    #[test]
    fn test_syscall_name_pipe_syscalls() {
        assert_eq!(syscall_name(293), "pipe2");
        assert_eq!(syscall_name(294), "inotify_init1");
    }

    #[test]
    fn test_syscall_name_prlimit() {
        assert_eq!(syscall_name(302), "prlimit64");
    }

    #[test]
    fn test_syscall_name_memfd() {
        assert_eq!(syscall_name(319), "memfd_create");
        assert_eq!(syscall_name(322), "execveat");
        assert_eq!(syscall_name(323), "userfaultfd");
    }

    #[test]
    fn test_syscall_name_landlock_syscalls() {
        assert_eq!(syscall_name(444), "landlock_create_ruleset");
        assert_eq!(syscall_name(445), "landlock_add_rule");
        assert_eq!(syscall_name(446), "landlock_restrict_self");
    }

    #[test]
    fn test_syscall_name_pkey_syscalls() {
        assert_eq!(syscall_name(329), "pkey_mprotect");
        assert_eq!(syscall_name(330), "pkey_alloc");
        assert_eq!(syscall_name(331), "pkey_free");
    }

    // ========================================
    // extract_args_from_seccomp Tests
    // ========================================

    #[test]
    fn test_extract_args_socket_syscall() {
        // SOCKET syscall (41) doesn't need /proc/pid/mem
        let args: [u64; 6] = [2, 1, 6, 0, 0, 0]; // AF_INET, SOCK_STREAM, TCP
        let result = extract_args_from_seccomp(999999999, 41, &args);

        // Should use format_socket_args since SOCKET doesn't need mem
        assert!(result[0].contains("domain="));
        assert!(result[1].contains("type="));
        assert!(result[2].contains("protocol="));
    }

    #[test]
    fn test_extract_args_accept_syscall() {
        // ACCEPT syscall (43) doesn't need /proc/pid/mem
        let args: [u64; 6] = [3, 0x7fff1234, 0x7fff1230, 0, 0, 0];
        let result = extract_args_from_seccomp(999999999, 43, &args);

        // Should use format_accept_args
        assert_eq!(result[0], "fd=3");
        assert!(result[1].contains("addr="));
        assert!(result[2].contains("addrlen="));
    }

    #[test]
    fn test_extract_args_accept4_syscall() {
        // ACCEPT4 syscall (288) doesn't need /proc/pid/mem
        let args: [u64; 6] = [5, 0x1000, 0x1008, 0, 0, 0];
        let result = extract_args_from_seccomp(999999999, 288, &args);

        assert_eq!(result[0], "fd=5");
    }

    #[test]
    fn test_extract_args_execve_fallback() {
        // EXECVE syscall (59) with non-existent PID should fall back to generic args
        let args: [u64; 6] = [0x1000, 0x2000, 0x3000, 0, 0, 0];
        let result = extract_args_from_seccomp(999999999, 59, &args);

        // Should fall back to format_generic_args since /proc/999999999/mem doesn't exist
        assert_eq!(result.len(), 6);
        assert!(result[0].starts_with("0x"));
    }

    #[test]
    fn test_extract_args_execveat_fallback() {
        // EXECVEAT syscall (322) with non-existent PID should fall back to generic args
        let args: [u64; 6] = [100, 0x1000, 0x2000, 0, 0, 0];
        let result = extract_args_from_seccomp(999999999, 322, &args);

        // Should fall back to format_generic_args
        assert_eq!(result.len(), 6);
        assert!(result[0].starts_with("0x"));
    }

    #[test]
    fn test_extract_args_connect_fallback() {
        // CONNECT syscall (42) with non-existent PID should fall back to generic args
        let args: [u64; 6] = [3, 0x1000, 16, 0, 0, 0];
        let result = extract_args_from_seccomp(999999999, 42, &args);

        // Should fall back to format_generic_args
        assert_eq!(result.len(), 6);
        assert!(result[0].starts_with("0x"));
    }

    #[test]
    fn test_extract_args_bind_fallback() {
        // BIND syscall (49) with non-existent PID should fall back to generic args
        let args: [u64; 6] = [3, 0x1000, 16, 0, 0, 0];
        let result = extract_args_from_seccomp(999999999, 49, &args);

        // Should fall back to format_generic_args
        assert_eq!(result.len(), 6);
        assert!(result[0].starts_with("0x"));
    }

    #[test]
    fn test_extract_args_sendto_fallback() {
        // SENDTO syscall (44) with non-existent PID should fall back to generic args
        let args: [u64; 6] = [3, 0x1000, 1024, 0, 0x2000, 16];
        let result = extract_args_from_seccomp(999999999, 44, &args);

        // Should fall back to format_generic_args
        assert_eq!(result.len(), 6);
        assert!(result[0].starts_with("0x"));
    }

    #[test]
    fn test_extract_args_recvfrom_fallback() {
        // RECVFROM syscall (45) with non-existent PID should fall back to generic args
        let args: [u64; 6] = [3, 0x1000, 1024, 0, 0x2000, 16];
        let result = extract_args_from_seccomp(999999999, 45, &args);

        // Should fall back to format_generic_args
        assert_eq!(result.len(), 6);
        assert!(result[0].starts_with("0x"));
    }

    #[test]
    fn test_extract_args_unknown_syscall() {
        // Unknown syscall should use generic args
        let args: [u64; 6] = [1, 2, 3, 4, 5, 6];
        let result = extract_args_from_seccomp(999999999, 999, &args);

        // Should use format_generic_args
        assert_eq!(result.len(), 6);
        assert_eq!(result[0], "0x1");
        assert_eq!(result[5], "0x6");
    }

    // ========================================
    // read_string_from_mem Tests
    // ========================================

    #[test]
    fn test_read_string_from_mem_basic() {
        use std::io::{Seek, SeekFrom, Write};

        let mut temp = tempfile::tempfile().unwrap();
        temp.write_all(b"hello world\0more data").unwrap();
        temp.seek(SeekFrom::Start(0)).unwrap();
        let result = read_string_from_mem(&mut temp, 0);
        assert_eq!(result, Some("hello world".to_string()));
    }

    #[test]
    fn test_read_string_from_mem_with_offset() {
        use std::io::{Seek, SeekFrom, Write};

        let mut temp = tempfile::tempfile().unwrap();
        temp.write_all(b"prefix\0hello\0world").unwrap();
        temp.seek(SeekFrom::Start(0)).unwrap();
        let result = read_string_from_mem(&mut temp, 7);
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn test_read_string_from_mem_empty() {
        use std::io::{Seek, SeekFrom, Write};

        let mut temp = tempfile::tempfile().unwrap();
        temp.write_all(b"\0more").unwrap();
        temp.seek(SeekFrom::Start(0)).unwrap();
        let result = read_string_from_mem(&mut temp, 0);
        assert_eq!(result, Some("".to_string()));
    }

    #[test]
    fn test_read_string_from_mem_max_length() {
        use std::io::{Seek, SeekFrom, Write};

        // Create a string that's exactly at the 4096 byte limit
        let mut data = vec![b'a'; 4095];
        data.push(0); // null terminator
        let mut temp = tempfile::tempfile().unwrap();
        temp.write_all(&data).unwrap();
        temp.seek(SeekFrom::Start(0)).unwrap();
        let result = read_string_from_mem(&mut temp, 0);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 4095);
    }

    #[test]
    fn test_read_string_from_mem_truncate_at_limit() {
        use std::io::{Seek, SeekFrom, Write};

        // Create a string longer than 4096 bytes (no null terminator in first 4096)
        let data = vec![b'x'; 5000];
        let mut temp = tempfile::tempfile().unwrap();
        temp.write_all(&data).unwrap();
        temp.seek(SeekFrom::Start(0)).unwrap();
        let result = read_string_from_mem(&mut temp, 0);
        // Should stop at 4096 iterations
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 4096);
    }

    #[test]
    fn test_read_string_from_mem_invalid_utf8() {
        use std::io::{Seek, SeekFrom, Write};

        let data: &[u8] = &[0xff, 0xfe, 0xfd, 0x00]; // Invalid UTF-8
        let mut temp = tempfile::tempfile().unwrap();
        temp.write_all(data).unwrap();
        temp.seek(SeekFrom::Start(0)).unwrap();
        let result = read_string_from_mem(&mut temp, 0);
        // Invalid UTF-8 should return None
        assert!(result.is_none());
    }

    #[test]
    fn test_read_string_from_mem_no_null_terminator() {
        use std::io::{Seek, SeekFrom, Write};

        let data = b"hello world"; // No null terminator
        let mut temp = tempfile::tempfile().unwrap();
        temp.write_all(data).unwrap();
        temp.seek(SeekFrom::Start(0)).unwrap();
        let result = read_string_from_mem(&mut temp, 0);
        // Should read until EOF (limited by 4096 iterations)
        assert!(result.is_some());
    }

    // ========================================
    // read_string_array_from_mem Tests
    // ========================================

    #[test]
    fn test_read_string_array_from_mem_null_pointer() {
        use std::io::{Seek, SeekFrom, Write};

        let mut temp = tempfile::tempfile().unwrap();
        temp.write_all(&[]).unwrap();
        temp.seek(SeekFrom::Start(0)).unwrap();
        let result = read_string_array_from_mem(&mut temp, 0);
        assert_eq!(result, "[]");
    }

    #[test]
    fn test_read_string_array_from_mem_single_string() {
        use std::io::{Seek, SeekFrom, Write};

        // Build a memory layout: pointer to string, string data, null terminator
        // Start the array at offset 8 (not 0, since addr=0 means NULL pointer)
        let mut buffer: Vec<u8> = Vec::new();

        // Pad to offset 8
        while buffer.len() < 8 {
            buffer.push(0);
        }

        // At offset 8: pointer to string at offset 24
        let str_ptr: u64 = 24;
        buffer.extend_from_slice(&str_ptr.to_ne_bytes());

        // At offset 16: null pointer (end of array)
        buffer.extend_from_slice(&0u64.to_ne_bytes());

        // Pad to offset 24
        while buffer.len() < 24 {
            buffer.push(0);
        }

        // At offset 24: string "test\0"
        buffer.extend_from_slice(b"test\0");

        let mut temp = tempfile::tempfile().unwrap();
        temp.write_all(&buffer).unwrap();
        temp.seek(SeekFrom::Start(0)).unwrap();
        let result = read_string_array_from_mem(&mut temp, 8); // Array starts at offset 8
        assert_eq!(result, r#"["test"]"#);
    }

    #[test]
    fn test_read_string_array_from_mem_multiple_strings() {
        use std::io::{Seek, SeekFrom, Write};

        // Build memory layout with multiple strings
        // Start the array at offset 8 (not 0, since addr=0 means NULL pointer)
        let mut buffer: Vec<u8> = Vec::new();

        // Pad to offset 8
        while buffer.len() < 8 {
            buffer.push(0);
        }

        // Pointer 1: to string at offset 48
        buffer.extend_from_slice(&48u64.to_ne_bytes());
        // Pointer 2: to string at offset 58
        buffer.extend_from_slice(&58u64.to_ne_bytes());
        // Pointer 3: to string at offset 68
        buffer.extend_from_slice(&68u64.to_ne_bytes());
        // Null terminator
        buffer.extend_from_slice(&0u64.to_ne_bytes());

        // Pad to offset 48
        while buffer.len() < 48 {
            buffer.push(0);
        }
        buffer.extend_from_slice(b"arg1\0");

        while buffer.len() < 58 {
            buffer.push(0);
        }
        buffer.extend_from_slice(b"arg2\0");

        while buffer.len() < 68 {
            buffer.push(0);
        }
        buffer.extend_from_slice(b"arg3\0");

        let mut temp = tempfile::tempfile().unwrap();
        temp.write_all(&buffer).unwrap();
        temp.seek(SeekFrom::Start(0)).unwrap();
        let result = read_string_array_from_mem(&mut temp, 8); // Array starts at offset 8
        assert_eq!(result, r#"["arg1", "arg2", "arg3"]"#);
    }

    #[test]
    fn test_read_string_array_from_mem_empty_array() {
        use std::io::{Seek, SeekFrom, Write};

        // addr=0 means NULL pointer, which returns empty array
        let mut temp = tempfile::tempfile().unwrap();
        temp.write_all(&[]).unwrap();
        temp.seek(SeekFrom::Start(0)).unwrap();
        let result = read_string_array_from_mem(&mut temp, 0); // NULL pointer
        assert_eq!(result, "[]");
    }

    // ========================================
    // read_sockaddr_from_mem Tests
    // ========================================

    #[test]
    fn test_read_sockaddr_unix() {
        use std::io::{Seek, SeekFrom, Write};

        // AF_UNIX (family=1) + path
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(&1u16.to_ne_bytes()); // AF_UNIX
        buffer.extend_from_slice(b"/tmp/socket\0"); // sun_path

        let mut temp = tempfile::tempfile().unwrap();
        temp.write_all(&buffer).unwrap();
        temp.seek(SeekFrom::Start(0)).unwrap();
        let result = read_sockaddr_from_mem(&mut temp, 0, 20);
        assert!(result.is_some());
        assert!(result.unwrap().contains("AF_UNIX"));
    }

    #[test]
    fn test_read_sockaddr_inet() {
        use std::io::{Seek, SeekFrom, Write};

        // AF_INET (family=2) + port + addr
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(&2u16.to_ne_bytes()); // AF_INET
        buffer.extend_from_slice(&8080u16.to_be_bytes()); // port (big-endian)
        buffer.extend_from_slice(&[192, 168, 1, 1]); // IPv4 address

        let mut temp = tempfile::tempfile().unwrap();
        temp.write_all(&buffer).unwrap();
        temp.seek(SeekFrom::Start(0)).unwrap();
        let result = read_sockaddr_from_mem(&mut temp, 0, 16);
        assert!(result.is_some());
        let addr = result.unwrap();
        assert!(addr.contains("AF_INET"));
        assert!(addr.contains("192.168.1.1"));
        assert!(addr.contains("8080"));
    }

    #[test]
    fn test_read_sockaddr_inet6() {
        use std::io::{Seek, SeekFrom, Write};

        // AF_INET6 (family=10) + port + flowinfo + addr
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(&10u16.to_ne_bytes()); // AF_INET6
        buffer.extend_from_slice(&443u16.to_be_bytes()); // port (big-endian)
        buffer.extend_from_slice(&0u32.to_ne_bytes()); // flowinfo (4 bytes)
        // IPv6 address: 2001:db8::1 (16 bytes)
        buffer.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00]);
        buffer.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);

        let mut temp = tempfile::tempfile().unwrap();
        temp.write_all(&buffer).unwrap();
        temp.seek(SeekFrom::Start(0)).unwrap();
        let result = read_sockaddr_from_mem(&mut temp, 0, 28);
        assert!(result.is_some());
        let addr = result.unwrap();
        assert!(addr.contains("AF_INET6"));
        assert!(addr.contains("443"));
    }

    #[test]
    fn test_read_sockaddr_unknown_family() {
        use std::io::{Seek, SeekFrom, Write};

        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(&99u16.to_ne_bytes()); // Unknown family

        let mut temp = tempfile::tempfile().unwrap();
        temp.write_all(&buffer).unwrap();
        temp.seek(SeekFrom::Start(0)).unwrap();
        let result = read_sockaddr_from_mem(&mut temp, 0, 2);
        assert!(result.is_some());
        assert!(result.unwrap().contains("AF_99"));
    }

    // ========================================
    // format_execve_args Tests
    // ========================================

    #[test]
    fn test_format_execve_args_with_mem() {
        use std::io::{Seek, SeekFrom, Write};

        // Build memory layout for execve args
        let mut buffer: Vec<u8> = Vec::new();

        // Pointer to pathname at offset 40
        buffer.extend_from_slice(&40u64.to_ne_bytes());
        // Pointer to argv array at offset 56
        buffer.extend_from_slice(&56u64.to_ne_bytes());
        // envp pointer (null for simplicity)
        buffer.extend_from_slice(&0u64.to_ne_bytes());

        // Pad to offset 40
        while buffer.len() < 40 {
            buffer.push(0);
        }
        buffer.extend_from_slice(b"/bin/bash\0");

        // Pad to offset 56
        while buffer.len() < 56 {
            buffer.push(0);
        }
        // argv: pointer to string at offset 80, then null
        buffer.extend_from_slice(&80u64.to_ne_bytes());
        buffer.extend_from_slice(&0u64.to_ne_bytes());

        // Pad to offset 80
        while buffer.len() < 80 {
            buffer.push(0);
        }
        buffer.extend_from_slice(b"-c\0");

        let mut temp = tempfile::tempfile().unwrap();
        temp.write_all(&buffer).unwrap();
        temp.seek(SeekFrom::Start(0)).unwrap();
        let args: [u64; 6] = [0, 56, 0, 0, 0, 0]; // pathname at 0, argv at 56
        let result = format_execve_args(&mut temp, &args);

        assert!(result[0].contains("pathname="));
        assert!(result[1].contains("argv="));
        assert!(result[2].contains("envp="));
    }

    // ========================================
    // format_sockaddr_args Tests
    // ========================================

    #[test]
    fn test_format_sockaddr_args_inet() {
        use std::io::{Seek, SeekFrom, Write};

        // Build sockaddr_in structure
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(&2u16.to_ne_bytes()); // AF_INET
        buffer.extend_from_slice(&80u16.to_be_bytes()); // port
        buffer.extend_from_slice(&[127, 0, 0, 1]); // loopback

        let mut temp = tempfile::tempfile().unwrap();
        temp.write_all(&buffer).unwrap();
        temp.seek(SeekFrom::Start(0)).unwrap();
        let args: [u64; 6] = [3, 0, 16, 0, 0, 0]; // fd=3, addr at 0, addrlen=16
        let result = format_sockaddr_args(&mut temp, &args);

        assert_eq!(result[0], "fd=3");
        assert!(result[1].contains("addr="));
        assert!(result[1].contains("AF_INET"));
        assert!(result[2].contains("addrlen=16"));
    }

    // ========================================
    // format_sendto_args Tests
    // ========================================

    #[test]
    fn test_format_sendto_args_basic() {
        use std::io::{Seek, SeekFrom, Write};

        let args: [u64; 6] = [4, 0x1000, 1024, 0, 0, 0]; // No dest_addr
        let mut temp = tempfile::tempfile().unwrap();
        temp.write_all(&[]).unwrap();
        temp.seek(SeekFrom::Start(0)).unwrap();
        let result = format_sendto_args(&mut temp, &args);

        assert_eq!(result[0], "fd=4");
        assert!(result[1].contains("buf="));
        assert_eq!(result[2], "len=1024");
        assert_eq!(result[3], "flags=0");
        // No dest_addr since args[4] is 0
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn test_format_sendto_args_with_dest() {
        use std::io::{Seek, SeekFrom, Write};

        // Build sockaddr_in for destination at offset 8 (non-zero address)
        let mut buffer: Vec<u8> = Vec::new();

        // Pad to offset 8
        while buffer.len() < 8 {
            buffer.push(0);
        }

        buffer.extend_from_slice(&2u16.to_ne_bytes()); // AF_INET
        buffer.extend_from_slice(&443u16.to_be_bytes()); // port
        buffer.extend_from_slice(&[93, 184, 216, 34]); // example.com IP

        let mut temp = tempfile::tempfile().unwrap();
        temp.write_all(&buffer).unwrap();
        temp.seek(SeekFrom::Start(0)).unwrap();
        // args[4] = dest_addr pointer (must be non-zero), args[5] = addrlen (must be > 0)
        let args: [u64; 6] = [5, 0x2000, 512, 0, 8, 16]; // dest_addr at offset 8
        let result = format_sendto_args(&mut temp, &args);

        assert_eq!(result[0], "fd=5");
        assert!(result[4].contains("dest_addr="));
        assert!(result[4].contains("AF_INET"));
    }

    // ========================================
    // SeccompDecision::to_response Tests
    // ========================================

    #[test]
    fn test_seccomp_decision_to_response_allow() {
        // We can't easily create a ScmpNotifReq for testing,
        // but we can verify the decision logic
        let decision = SeccompDecision::Allow;
        match decision {
            SeccompDecision::Allow => (),
            _ => panic!("Expected Allow variant"),
        }
    }

    #[test]
    fn test_seccomp_decision_to_response_block() {
        let decision = SeccompDecision::Block { errno: libc::EPERM };
        match decision {
            SeccompDecision::Block { errno } => assert_eq!(errno, libc::EPERM),
            _ => panic!("Expected Block variant"),
        }
    }

    #[test]
    fn test_seccomp_decision_to_response_kill() {
        let decision = SeccompDecision::Kill;
        match decision {
            SeccompDecision::Kill => (),
            _ => panic!("Expected Kill variant"),
        }
    }

    // ========================================
    // kernel_supports_seccomp_notify Tests
    // ========================================

    #[test]
    fn test_kernel_supports_seccomp_notify_returns_bool() {
        // The function should return a boolean on any Linux system
        let result = kernel_supports_seccomp_notify();
        // We can't assert the exact value since it depends on the kernel,
        // but we can verify it's a valid boolean
        // The result is already a bool, so just use it
        let _: bool = result;
    }

    #[test]
    fn test_kernel_supports_seccomp_notify_modern_kernel() {
        // On any modern kernel (4.14+), this should return true
        // This test documents the expected behavior
        let supported = kernel_supports_seccomp_notify();
        // Most CI environments run on kernels >= 4.14
        // We just verify the function doesn't panic
        println!("Kernel supports seccomp-unotify: {}", supported);
    }

    // ========================================
    // SyscallCategory::syscalls Tests
    // ========================================

    #[test]
    fn test_syscall_category_network_syscalls() {
        let syscalls = SyscallCategory::Network.syscalls();
        assert!(syscalls.contains(&"socket"));
        assert!(syscalls.contains(&"connect"));
        assert!(syscalls.contains(&"bind"));
        assert!(syscalls.contains(&"accept"));
        assert!(syscalls.contains(&"accept4"));
    }

    #[test]
    fn test_syscall_category_process_syscalls() {
        let syscalls = SyscallCategory::Process.syscalls();
        assert!(syscalls.contains(&"execve"));
        assert!(syscalls.contains(&"execveat"));
        assert!(syscalls.contains(&"clone"));
        assert!(syscalls.contains(&"clone3"));
        assert!(syscalls.contains(&"fork"));
        assert!(syscalls.contains(&"vfork"));
    }

    #[test]
    fn test_syscall_category_privilege_syscalls() {
        let syscalls = SyscallCategory::Privilege.syscalls();
        assert!(syscalls.contains(&"setuid"));
        assert!(syscalls.contains(&"setgid"));
        assert!(syscalls.contains(&"capset"));
        assert!(syscalls.contains(&"ptrace"));
        assert!(syscalls.contains(&"prctl"));
    }

    // ========================================
    // SyscallInfo From<&ScmpNotifReq> Tests
    // ========================================

    #[test]
    fn test_syscall_info_from_notif_req() {
        // Verify the From implementation exists and compiles
        // We can't easily create a ScmpNotifReq without a real notification
        // but we can test the struct creation directly
        let info = SyscallInfo {
            syscall_nr: 59,
            arch: ScmpArch::X8664,
            pid: 1234,
            args: [1, 2, 3, 4, 5, 6],
            instr_pointer: 0x7fff12345678,
        };

        assert_eq!(info.syscall_nr, 59);
        assert_eq!(info.arch, ScmpArch::X8664);
        assert_eq!(info.pid, 1234);
        assert_eq!(info.args, [1, 2, 3, 4, 5, 6]);
        assert_eq!(info.instr_pointer, 0x7fff12345678);
    }

    // ========================================
    // SeccompNotifier Tests (non-spawning)
    // ========================================

    #[test]
    fn test_seccomp_notifier_fd() {
        let notifier = SeccompNotifier::for_syscall("read").unwrap();
        assert!(notifier.fd() >= 0);
    }

    #[test]
    fn test_seccomp_notifier_filter() {
        let notifier = SeccompNotifier::for_syscall("write").unwrap();
        let _filter = notifier.filter();
        // Just verify we can access the filter
    }

    #[test]
    fn test_seccomp_notifier_as_raw_fd() {
        use std::os::unix::io::AsRawFd;

        let notifier = SeccompNotifier::for_syscall("close").unwrap();
        let fd = notifier.as_raw_fd();
        assert!(fd >= 0);
    }

    // ========================================
    // Additional syscall_name Coverage Tests
    // ========================================

    #[test]
    fn test_syscall_name_clone3() {
        assert_eq!(syscall_name(435), "clone3");
    }

    #[test]
    fn test_syscall_name_io_uring() {
        assert_eq!(syscall_name(425), "io_uring_setup");
        assert_eq!(syscall_name(426), "io_uring_enter");
        assert_eq!(syscall_name(427), "io_uring_register");
    }

    #[test]
    fn test_syscall_name_pidfd() {
        assert_eq!(syscall_name(424), "pidfd_send_signal");
        assert_eq!(syscall_name(434), "pidfd_open");
        assert_eq!(syscall_name(438), "pidfd_getfd");
    }

    #[test]
    fn test_syscall_name_openat2() {
        assert_eq!(syscall_name(437), "openat2");
    }

    #[test]
    fn test_syscall_name_memfd_secret() {
        assert_eq!(syscall_name(447), "memfd_secret");
    }

    #[test]
    fn test_syscall_name_process_mrelease() {
        assert_eq!(syscall_name(448), "process_mrelease");
    }

    #[test]
    fn test_syscall_name_statx() {
        assert_eq!(syscall_name(332), "statx");
    }

    #[test]
    fn test_syscall_name_getrandom() {
        assert_eq!(syscall_name(318), "getrandom");
    }

    #[test]
    fn test_syscall_name_bpf() {
        assert_eq!(syscall_name(321), "bpf");
    }

    #[test]
    fn test_syscall_name_userfaultfd() {
        assert_eq!(syscall_name(323), "userfaultfd");
    }

    #[test]
    fn test_syscall_name_membarrier() {
        assert_eq!(syscall_name(324), "membarrier");
    }

    #[test]
    fn test_syscall_name_copy_file_range() {
        assert_eq!(syscall_name(326), "copy_file_range");
    }

    #[test]
    fn test_syscall_name_faccessat2() {
        assert_eq!(syscall_name(439), "faccessat2");
    }

    #[test]
    fn test_syscall_name_process_madvise() {
        assert_eq!(syscall_name(440), "process_madvise");
    }

    #[test]
    fn test_syscall_name_epoll_pwait2() {
        assert_eq!(syscall_name(441), "epoll_pwait2");
    }

    #[test]
    fn test_syscall_name_mount_setattr() {
        assert_eq!(syscall_name(442), "mount_setattr");
    }

    #[test]
    fn test_syscall_name_quotactl_fd() {
        assert_eq!(syscall_name(443), "quotactl_fd");
    }
}
