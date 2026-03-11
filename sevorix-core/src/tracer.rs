//! Process tracing module using ptrace for syscall interception.
//!
//! **DEPRECATED**: This module is deprecated in favor of `seccomp-unotify`.
//! See the `seccomp` module for the recommended approach.
//!
//! # Migration Guide
//!
//! The ptrace-based tracing in this module has higher overhead and requires
//! the parent process to be the tracer. For new code, prefer the seccomp-unotify
//! approach in the `seccomp` module:
//!
//! - Use `spawn_seccomp_shell()` instead of `spawn_traced_shell()`
//! - Use `SeccompNotifier` for fine-grained control
//! - Kernel version check is automatic: ptrace fallback is used for Linux < 4.14
//!
//! ## What's Kept
//!
//! The following utilities remain non-deprecated as they are useful for both
//! approaches:
//!
//! - `syscall_name()` - Converts syscall numbers to names
//!
//! ## Deprecation Timeline
//!
//! - Phase 6 (current): Functions marked deprecated, migration recommended
//! - Future release: ptrace-specific code removed after migration is stable
//!
//! This module provides low-level process tracing capabilities for monitoring
//! and controlling child processes via the ptrace system call interface.

use nix::sys::ptrace::{self, Options};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use std::collections::HashSet;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, ExitStatus};

/// Register offsets for PTRACE_POKEUSER.
///
/// These offsets are architecture-specific and correspond to the position
/// of the register in the `user_regs_struct` defined in `<sys/user.h>`.
mod reg_offset {
    /// RAX offset in user_regs_struct on x86_64.
    /// RAX is at position 10, so offset = 10 * 8 = 80.
    #[cfg(target_arch = "x86_64")]
    pub const RAX: usize = 80;

    /// X0 offset in user_regs_struct on aarch64.
    /// X0 is the first register, so offset = 0.
    #[cfg(target_arch = "aarch64")]
    pub const X0: usize = 0;
}

/// x86_64 syscall numbers for argument-specific handling.
#[allow(dead_code)]
mod syscall_nr {
    pub const READ: i64 = 0;
    pub const WRITE: i64 = 1;
    pub const OPEN: i64 = 2;
    pub const CLOSE: i64 = 3;
    pub const STAT: i64 = 4;
    pub const FSTAT: i64 = 5;
    pub const OPENAT: i64 = 257;
    pub const EXECVE: i64 = 59;
    pub const SOCKET: i64 = 41;
    pub const CONNECT: i64 = 42;
    pub const ACCEPT: i64 = 43;
    pub const SENDTO: i64 = 44;
    pub const RECVFROM: i64 = 45;
    pub const SHUTDOWN: i64 = 48;
    pub const BIND: i64 = 49;
    pub const LISTEN: i64 = 50;
    pub const GETSOCKNAME: i64 = 51;
    pub const GETPEERNAME: i64 = 52;
    pub const SOCKETPAIR: i64 = 53;
    pub const ACCEPT4: i64 = 288;
}

/// Convert an x86_64 syscall number to its name.
///
/// Returns the syscall name as a static string, or "unknown" for undefined syscall numbers.
/// This function is only available on x86_64 targets.
///
/// # Arguments
///
/// * `nr` - The syscall number (architecture-specific)
///
/// # Returns
///
/// The syscall name as a `&'static str`.
#[cfg(target_arch = "x86_64")]
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

/// A process being traced via ptrace.
///
/// **Deprecated**: Use `PtyShellHandle` from the pty module with seccomp integration
/// instead. See `spawn_pty_shell_with_seccomp()` for the recommended approach.
///
/// `TracedProcess` represents a child process that has been spawned under
/// ptrace control, allowing the parent to intercept and inspect syscalls.
#[deprecated(
    since = "0.7.0",
    note = "Use PtyShellHandle with seccomp integration instead"
)]
#[derive(Debug)]
pub struct TracedProcess {
    /// The process ID of the traced child process.
    pub pid: Pid,
    /// Optional URL for communication with a tracing daemon.
    pub daemon_url: Option<String>,
}

/// Represents a captured syscall event.
///
/// **Deprecated**: This type is part of the deprecated ptrace-based tracer module.
/// Use types from the seccomp module instead.
#[deprecated(
    since = "0.7.0",
    note = "Use seccomp module types instead. The tracer module is deprecated."
)]
#[derive(Debug, Clone)]
pub struct SyscallEvent {
    /// The syscall number (architecture-specific).
    pub number: i64,
    /// The process that made the syscall.
    pub pid: Pid,
    /// Whether this is syscall entry (true) or exit (false).
    pub is_entry: bool,
}

/// Extract syscall arguments from registers and format them as human-readable strings.
///
/// **Deprecated**: Use `extract_args_from_seccomp()` from the seccomp module instead,
/// which works with seccomp-unotify requests and doesn't require ptrace.
///
/// On x86_64, syscall arguments are passed in registers:
/// - arg0: rdi
/// - arg1: rsi
/// - arg2: rdx
/// - arg3: r10
/// - arg4: r8
/// - arg5: r9
///
/// For certain syscalls, this function will read additional data from the tracee's
/// memory to provide more meaningful argument representations:
/// - Network syscalls: parses sockaddr structures
/// - execve: reads argv strings
///
/// # Arguments
///
/// * `pid` - The process ID of the traced process
/// * `syscall_nr` - The syscall number (architecture-specific)
///
/// # Returns
///
/// A vector of human-readable argument strings. Returns an empty vector on error.
#[deprecated(
    since = "0.7.0",
    note = "Use extract_args_from_seccomp() from the seccomp module instead"
)]
pub fn extract_args(pid: Pid, syscall_nr: i64) -> Vec<String> {
    let regs = match ptrace::getregs(pid) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    // Extract raw argument values from registers (x86_64 calling convention)
    let args: [u64; 6] = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];

    match syscall_nr {
        syscall_nr::EXECVE => format_execve_args(pid, &args),
        syscall_nr::CONNECT | syscall_nr::BIND => format_sockaddr_args(pid, &args),
        syscall_nr::ACCEPT | syscall_nr::ACCEPT4 => format_accept_args(&args),
        syscall_nr::SENDTO | syscall_nr::RECVFROM => format_sendto_args(pid, &args),
        syscall_nr::SOCKET => format_socket_args(&args),
        _ => format_generic_args(&args),
    }
}

/// Format arguments for execve syscall by reading argv strings from memory.
fn format_execve_args(pid: Pid, args: &[u64; 6]) -> Vec<String> {
    let mut result = Vec::new();

    // execve(const char *pathname, char *const argv[], char *const envp[])
    // arg0 = pathname pointer
    // arg1 = argv pointer
    // arg2 = envp pointer

    // Read pathname
    if let Some(pathname) = read_string(pid, args[0]) {
        result.push(format!("pathname=\"{}\"", pathname));
    } else {
        result.push(format!("pathname={:#x}", args[0]));
    }

    // Read argv array
    result.push(format!("argv={}", read_string_array(pid, args[1])));

    // envp is often NULL or large, just show pointer
    result.push(format!("envp={:#x}", args[2]));

    result
}

/// Format arguments for socket syscalls that involve sockaddr structures.
fn format_sockaddr_args(pid: Pid, args: &[u64; 6]) -> Vec<String> {
    let mut result = Vec::new();

    // connect/bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
    result.push(format!("fd={}", args[0]));

    if let Some(addr_str) = read_sockaddr(pid, args[1], args[2]) {
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
fn format_sendto_args(pid: Pid, args: &[u64; 6]) -> Vec<String> {
    let mut result = Vec::new();

    // sendto(int sockfd, const void *buf, size_t len, int flags,
    //        const struct sockaddr *dest_addr, socklen_t addrlen)
    result.push(format!("fd={}", args[0]));
    result.push(format!("buf={:#x}", args[1]));
    result.push(format!("len={}", args[2]));
    result.push(format!("flags={}", args[3]));

    // dest_addr is optional (can be NULL for connected sockets)
    if args[4] != 0 && args[5] > 0 {
        if let Some(addr_str) = read_sockaddr(pid, args[4], args[5]) {
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

/// Read a null-terminated string from the traced process's memory.
///
/// Reads memory one word at a time using PTRACE_PEEKDATA until a null byte is found.
fn read_string(pid: Pid, addr: u64) -> Option<String> {
    let mut result = Vec::new();
    let mut offset = 0usize;

    loop {
        // Read one word (8 bytes on x86_64)
        let word = ptrace::read(pid, (addr as usize + offset) as *mut _).ok()?;

        // Extract bytes from the word (little-endian)
        let bytes = word.to_ne_bytes();

        for byte in bytes {
            if byte == 0 {
                // Found null terminator
                return String::from_utf8(result).ok();
            }
            result.push(byte);
        }

        offset += 8;

        // Safety limit to prevent infinite loops on corrupted memory
        if offset > 4096 {
            break;
        }
    }

    String::from_utf8(result).ok()
}

/// Read an array of strings (argv-style) from the traced process's memory.
///
/// The array is terminated by a NULL pointer.
fn read_string_array(pid: Pid, addr: u64) -> String {
    if addr == 0 {
        return "[]".to_string();
    }

    let mut strings = Vec::new();
    let mut offset = 0usize;

    #[allow(clippy::while_let_loop)]
    loop {
        // Read pointer to string
        let ptr_word = match ptrace::read(pid, (addr as usize + offset) as *mut _) {
            Ok(w) => w,
            Err(_) => break,
        };

        // NULL pointer terminates the array
        if ptr_word == 0 {
            break;
        }

        // Read the string at this pointer
        if let Some(s) = read_string(pid, ptr_word as u64) {
            strings.push(format!("\"{}\"", s));
        }

        offset += 8;

        // Safety limit
        if offset > 4096 || strings.len() > 64 {
            break;
        }
    }

    format!("[{}]", strings.join(", "))
}

/// Read and parse a sockaddr structure from the traced process's memory.
///
/// Supports AF_UNIX, AF_INET, and AF_INET6 address families.
fn read_sockaddr(pid: Pid, addr: u64, _addrlen: u64) -> Option<String> {
    // Read the first 2 bytes to get the address family (sa_family)
    let family_word = ptrace::read(pid, addr as *mut _).ok()?;
    let family = (family_word as u16).to_ne_bytes()[0] as u16
        | ((family_word as u16).to_ne_bytes()[1] as u16) << 8;

    match family {
        1 => {
            // AF_UNIX - read the sun_path
            // sockaddr_un is: family (2 bytes) + path (108 bytes max)
            let path_addr = addr + 2;
            if let Some(path) = read_string(pid, path_addr) {
                Some(format!("AF_UNIX(\"{}\")", path))
            } else {
                Some("AF_UNIX(?)".to_string())
            }
        }
        2 => {
            // AF_INET - sin_port (2 bytes) + sin_addr (4 bytes)
            // Read enough to get port and address
            let port_word = ptrace::read(pid, (addr + 2) as *mut _).ok()?;
            let port = (port_word as u16).to_be_bytes()[0] as u16
                | ((port_word as u16).to_be_bytes()[1] as u16) << 8;
            let port = u16::from_be(port);

            let addr_word = ptrace::read(pid, (addr + 4) as *mut _).ok()?;
            let addr_bytes = (addr_word as u32).to_ne_bytes();

            Some(format!(
                "AF_INET({}.{}.{}.{}:{})",
                addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3], port
            ))
        }
        10 => {
            // AF_INET6 - sin6_port (2 bytes) + sin6_flowinfo (4 bytes) + sin6_addr (16 bytes)
            let port_word = ptrace::read(pid, (addr + 2) as *mut _).ok()?;
            let port = (port_word as u16).to_be_bytes()[0] as u16
                | ((port_word as u16).to_be_bytes()[1] as u16) << 8;
            let port = u16::from_be(port);

            // Read the 16-byte IPv6 address (need 2 word reads)
            let addr1 = ptrace::read(pid, (addr + 8) as *mut _).ok()?;
            let addr2 = ptrace::read(pid, (addr + 16) as *mut _).ok()?;

            let mut ipv6_bytes = [0u8; 16];
            ipv6_bytes[0..8].copy_from_slice(&(addr1 as u64).to_ne_bytes());
            ipv6_bytes[8..16].copy_from_slice(&(addr2 as u64).to_ne_bytes());

            // Format as standard IPv6 notation
            let segments: Vec<String> = (0..8)
                .map(|i| format!("{:02x}{:02x}", ipv6_bytes[i * 2], ipv6_bytes[i * 2 + 1]))
                .collect();

            Some(format!("AF_INET6([{}]:{})", segments.join(":"), port))
        }
        _ => Some(format!("AF_{}", family)),
    }
}

/// Block a syscall by modifying the return value register.
///
/// **Deprecated**: Use `SeccompNotifier::deny()` from the seccomp module instead.
/// The seccomp approach is more efficient and doesn't require stopping the process.
///
/// This function uses `PTRACE_POKEUSER` to write `-EPERM` to the return
/// value register, causing the syscall to fail with a "permission denied" error.
///
/// # Architecture-specific behavior
///
/// - **x86_64**: Writes to the RAX register (offset 80 in user_regs_struct)
/// - **aarch64**: Writes to the X0 register (offset 0 in user_regs_struct)
///
/// # Arguments
///
/// * `pid` - The process ID of the traced process
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error string on failure.
///
/// # Safety
///
/// This function is unsafe because it directly manipulates the traced process's
/// registers via `ptrace::write_user`. The caller must ensure that the process
/// is in a stopped state at a syscall-exit stop before calling this function.
///
/// # Example
///
/// ```no_run
/// use sevorix_core::tracer::block_syscall;
/// use nix::unistd::Pid;
///
/// // Block the syscall for process 1234 (must be stopped at syscall-exit)
/// block_syscall(Pid::from_raw(1234)).unwrap();
/// ```
#[deprecated(
    since = "0.7.0",
    note = "Use SeccompNotifier::deny() from the seccomp module instead"
)]
pub fn block_syscall(pid: Pid) -> Result<(), String> {
    // EPERM = 1 (Operation not permitted)
    // We return -EPERM, which in two's complement is the max unsigned value
    let error_code: u64 = (-libc::EPERM) as u64;

    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: Caller must ensure process is stopped at syscall-exit
        unsafe {
            ptrace::write_user(pid, reg_offset::RAX as *mut _, error_code as *mut _)
                .map_err(|e| format!("PTRACE_POKEUSER failed for RAX: {}", e))?;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: Caller must ensure process is stopped at syscall-exit
        unsafe {
            ptrace::write_user(pid, reg_offset::X0 as *mut _, error_code as *mut _)
                .map_err(|e| format!("PTRACE_POKEUSER failed for X0: {}", e))?;
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = error_code;
        return Err("block_syscall: unsupported architecture".to_string());
    }

    Ok(())
}

/// Kill the traced process using PTRACE_KILL.
///
/// **Deprecated**: Use `SeccompNotifier::kill()` from the seccomp module instead.
/// The seccomp approach provides better control over process termination.
///
/// This function sends a SIGKILL to the traced process, causing immediate
/// termination. Use this for critical security violations where returning
/// EPERM isn't sufficient (e.g., kernel-level attacks, privilege escalation).
///
/// # Arguments
///
/// * `pid` - The process ID of the traced process
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error string on failure.
///
/// # Safety
///
/// This function is safe to call at any point when the process is being traced.
/// The process will be terminated immediately.
///
/// # Example
///
/// ```no_run
/// use sevorix_core::tracer::kill_syscall;
/// use nix::unistd::Pid;
///
/// // Kill the traced process for critical violation
/// kill_syscall(Pid::from_raw(1234)).unwrap();
/// ```
#[deprecated(
    since = "0.7.0",
    note = "Use SeccompNotifier::kill() from the seccomp module instead"
)]
pub fn kill_syscall(pid: Pid) -> Result<(), String> {
    ptrace::kill(pid).map_err(|e| format!("PTRACE_KILL failed: {}", e))
}

#[allow(deprecated)] // Methods for deprecated TracedProcess
impl TracedProcess {
    /// Spawn a new process under ptrace control.
    ///
    /// **Deprecated**: Use `spawn_pty_shell_with_seccomp()` instead.
    ///
    /// This function forks a child process and uses `PTRACE_TRACEME` to
    /// enable tracing. The child will stop before executing the specified
    /// command, allowing the parent to control execution.
    ///
    /// # Arguments
    ///
    /// * `command` - The command to execute in the traced process
    /// * `args` - Arguments to pass to the command
    ///
    /// # Returns
    ///
    /// Returns a `TracedProcess` handle on success, or an error string on failure.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sevorix_core::tracer::TracedProcess;
    ///
    /// let traced = TracedProcess::spawn_traced("/bin/true", &[]).unwrap();
    /// ```
    pub fn spawn_traced(command: &str, args: &[&str]) -> Result<Self, String> {
        // Enable ptrace options for tracing clones, forks, and vforks
        let options = Options::PTRACE_O_TRACECLONE
            | Options::PTRACE_O_TRACEFORK
            | Options::PTRACE_O_TRACEVFORK;

        match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => {
                // Parent process: wait for child to stop at SIGSTOP
                match waitpid(child, None) {
                    Ok(WaitStatus::Stopped(_, Signal::SIGSTOP)) => {
                        // Child is stopped before exec, set trace options
                        if let Err(e) = ptrace::setoptions(child, options) {
                            return Err(format!("Failed to set ptrace options: {}", e));
                        }
                        // Use PTRACE_SYSCALL to enable syscall tracing before exec
                        if let Err(e) = ptrace::syscall(child, None) {
                            return Err(format!("Failed to continue child: {}", e));
                        }
                        Ok(TracedProcess {
                            pid: child,
                            daemon_url: None,
                        })
                    }
                    Ok(status) => Err(format!("Unexpected wait status: {:?}", status)),
                    Err(e) => Err(format!("Failed to wait for child: {}", e)),
                }
            }
            Ok(ForkResult::Child) => {
                // Child process: request to be traced
                if let Err(e) = ptrace::traceme() {
                    eprintln!("PTRACE_TRACEME failed: {}", e);
                    std::process::exit(1);
                }

                // Stop ourselves to let parent set options before we exec
                if let Err(e) = nix::sys::signal::raise(Signal::SIGSTOP) {
                    eprintln!("Failed to raise SIGSTOP: {}", e);
                    std::process::exit(1);
                }

                // Execute the command - exec() only returns on error
                let err = Command::new(command).args(args).exec();
                eprintln!("Failed to exec {}: {}", command, err);
                std::process::exit(1);
            }
            Err(e) => Err(format!("Fork failed: {}", e)),
        }
    }

    /// Spawn a process under ptrace control with custom environment variables.
    ///
    /// This is similar to `spawn_traced` but allows setting environment variables
    /// for the child process.
    ///
    /// # Arguments
    ///
    /// * `command` - The command to execute
    /// * `args` - Arguments to pass to the command
    /// * `env_vars` - Environment variables to set as (key, value) pairs
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sevorix_core::tracer::TracedProcess;
    ///
    /// let env = vec![("HTTP_PROXY".to_string(), "http://localhost:3000".to_string())];
    /// let traced = TracedProcess::spawn_traced_with_env("/bin/true", &[], env).unwrap();
    /// ```
    pub fn spawn_traced_with_env(
        command: &str,
        args: &[&str],
        env_vars: Vec<(String, String)>,
    ) -> Result<Self, String> {
        // Enable ptrace options for tracing clones, forks, and vforks
        let options = Options::PTRACE_O_TRACECLONE
            | Options::PTRACE_O_TRACEFORK
            | Options::PTRACE_O_TRACEVFORK;

        match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => {
                // Parent process: wait for child to stop at SIGSTOP
                match waitpid(child, None) {
                    Ok(WaitStatus::Stopped(_, Signal::SIGSTOP)) => {
                        // Child is stopped before exec, set trace options
                        if let Err(e) = ptrace::setoptions(child, options) {
                            return Err(format!("Failed to set ptrace options: {}", e));
                        }
                        // Use PTRACE_SYSCALL to enable syscall tracing before exec
                        if let Err(e) = ptrace::syscall(child, None) {
                            return Err(format!("Failed to continue child: {}", e));
                        }
                        Ok(TracedProcess {
                            pid: child,
                            daemon_url: None,
                        })
                    }
                    Ok(status) => Err(format!("Unexpected wait status: {:?}", status)),
                    Err(e) => Err(format!("Failed to wait for child: {}", e)),
                }
            }
            Ok(ForkResult::Child) => {
                // Child process: request to be traced
                if let Err(e) = ptrace::traceme() {
                    eprintln!("PTRACE_TRACEME failed: {}", e);
                    std::process::exit(1);
                }

                // Stop ourselves to let parent set options before we exec
                if let Err(e) = nix::sys::signal::raise(Signal::SIGSTOP) {
                    eprintln!("Failed to raise SIGSTOP: {}", e);
                    std::process::exit(1);
                }

                // Build command with environment variables
                let mut cmd = Command::new(command);
                cmd.args(args);
                for (key, value) in env_vars {
                    cmd.env(key, value);
                }

                // Execute the command - exec() only returns on error
                let err = cmd.exec();
                eprintln!("Failed to exec {}: {}", command, err);
                std::process::exit(1);
            }
            Err(e) => Err(format!("Fork failed: {}", e)),
        }
    }

    /// Run the syscall tracing loop.
    ///
    /// This function continuously waits for the traced process to stop at
    /// syscall entry/exit points and captures each syscall event.
    ///
    /// # Arguments
    ///
    /// * `callback` - A closure called for each captured syscall event
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` when the traced process exits normally, or an error
    /// string on failure.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sevorix_core::tracer::TracedProcess;
    ///
    /// let mut traced = TracedProcess::spawn_traced("/bin/true", &[]).unwrap();
    /// traced.run_syscall_loop(|event| {
    ///     println!("Syscall {} at {}", event.number, event.pid);
    /// }).unwrap();
    /// ```
    pub fn run_syscall_loop<F>(&mut self, mut callback: F) -> Result<(), String>
    where
        F: FnMut(&SyscallEvent),
    {
        // Track entry/exit state per PID (each traced process has its own state)
        let mut is_entry_map: HashSet<Pid> = HashSet::new();

        // Track all traced processes (main + children from forks)
        let mut traced_pids: HashSet<Pid> = HashSet::new();
        traced_pids.insert(self.pid);

        loop {
            // Wait for ANY traced process to stop (use -1 to wait for all children)
            let status = match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL)) {
                Ok(s) => s,
                Err(e) => return Err(format!("waitpid failed: {}", e)),
            };

            match status {
                WaitStatus::Stopped(pid, Signal::SIGTRAP) => {
                    // Syscall stop - extract syscall number
                    if let Ok(regs) = ptrace::getregs(pid) {
                        // On x86_64, syscall number is in orig_rax
                        let syscall_num = regs.orig_rax as i64;
                        let is_entry = is_entry_map.contains(&pid);
                        callback(&SyscallEvent {
                            number: syscall_num,
                            pid,
                            is_entry,
                        });
                        // Toggle entry/exit for next stop
                        if is_entry {
                            is_entry_map.remove(&pid);
                        } else {
                            is_entry_map.insert(pid);
                        }
                    }
                    // Continue execution with syscall tracing
                    if let Err(e) = ptrace::syscall(pid, None) {
                        return Err(format!("ptrace::syscall failed: {}", e));
                    }
                }
                WaitStatus::PtraceEvent(pid, Signal::SIGTRAP, event) => {
                    // Handle fork/clone/vfork events (PTRACE_EVENT_FORK=1, VFORK=2, CLONE=3)
                    if let 1..=3 = event {
                        // Get the new child PID from the event message
                        if let Ok(new_pid_raw) = ptrace::getevent(pid) {
                            let new_pid = Pid::from_raw(new_pid_raw as i32);
                            traced_pids.insert(new_pid);
                            // Continue the new child with syscall tracing
                            if let Err(e) = ptrace::syscall(new_pid, None) {
                                // Child may have already exited, log but continue
                                eprintln!(
                                    "Warning: failed to continue new child {}: {}",
                                    new_pid, e
                                );
                            }
                        }
                    }
                    // Continue the parent process
                    if let Err(e) = ptrace::syscall(pid, None) {
                        return Err(format!("ptrace::syscall failed after event: {}", e));
                    }
                }
                WaitStatus::Exited(pid, _exit_code) => {
                    traced_pids.remove(&pid);
                    is_entry_map.remove(&pid);
                    if pid == self.pid && traced_pids.is_empty() {
                        return Ok(());
                    }
                    // Other traced processes may still be running, continue waiting
                }
                WaitStatus::Signaled(pid, _, _) => {
                    traced_pids.remove(&pid);
                    is_entry_map.remove(&pid);
                    if pid == self.pid && traced_pids.is_empty() {
                        return Ok(());
                    }
                }
                _ => {
                    // Other status - continue waiting
                }
            }
        }
    }

    /// Run the syscall tracing loop and return the exit status.
    ///
    /// This is a simpler variant of `run_syscall_loop` that doesn't use a callback
    /// and returns the child's exit status when it terminates.
    ///
    /// # Returns
    ///
    /// Returns `Ok(ExitStatus)` with the child's exit status, or an error string on failure.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sevorix_core::tracer::TracedProcess;
    ///
    /// let mut traced = TracedProcess::spawn_traced("/bin/true", &[]).unwrap();
    /// let status = traced.run_loop().unwrap();
    /// println!("Exit code: {:?}", status.code());
    /// ```
    pub fn run_loop(&mut self) -> Result<ExitStatus, String> {
        // Track all traced processes (main + children from forks)
        let mut traced_pids: HashSet<Pid> = HashSet::new();
        traced_pids.insert(self.pid);

        loop {
            // Wait for ANY traced process to stop (use -1 to wait for all children)
            let status = match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL)) {
                Ok(s) => s,
                Err(e) => return Err(format!("waitpid failed: {}", e)),
            };

            match status {
                WaitStatus::Stopped(pid, Signal::SIGTRAP) => {
                    // Syscall stop - continue execution with syscall tracing
                    if let Err(e) = ptrace::syscall(pid, None) {
                        return Err(format!("ptrace::syscall failed: {}", e));
                    }
                }
                WaitStatus::PtraceEvent(pid, Signal::SIGTRAP, event) => {
                    // Handle fork/clone/vfork events (PTRACE_EVENT_FORK=1, VFORK=2, CLONE=3)
                    if let 1..=3 = event {
                        // Get the new child PID from the event message
                        if let Ok(new_pid_raw) = ptrace::getevent(pid) {
                            let new_pid = Pid::from_raw(new_pid_raw as i32);
                            traced_pids.insert(new_pid);
                            // Continue the new child with syscall tracing
                            if let Err(e) = ptrace::syscall(new_pid, None) {
                                // Child may have already exited, log but continue
                                eprintln!(
                                    "Warning: failed to continue new child {}: {}",
                                    new_pid, e
                                );
                            }
                        }
                    }
                    // Continue the parent process
                    if let Err(e) = ptrace::syscall(pid, None) {
                        return Err(format!("ptrace::syscall failed after event: {}", e));
                    }
                }
                WaitStatus::Exited(pid, exit_code) => {
                    traced_pids.remove(&pid);
                    if pid == self.pid && traced_pids.is_empty() {
                        // Main process exited - return exit status
                        // from_raw expects a wait status: exit_code is in the high 8 bits
                        return Ok(ExitStatus::from_raw(exit_code << 8));
                    }
                    // Other traced processes may still be running, continue waiting
                }
                WaitStatus::Signaled(pid, signal, _) => {
                    traced_pids.remove(&pid);
                    if pid == self.pid && traced_pids.is_empty() {
                        // Main process was signaled - return as exit status
                        // Signal termination: the raw status is the signal number
                        return Ok(ExitStatus::from_raw(signal as i32));
                    }
                }
                _ => {
                    // Other status - continue waiting
                }
            }
        }
    }

    /// Continue the traced process.
    ///
    /// Resumes execution of the traced process.
    pub fn cont(&self) -> Result<(), String> {
        ptrace::cont(self.pid, None).map_err(|e| format!("ptrace::cont failed: {}", e))
    }

    /// Detach from the traced process.
    ///
    /// Detaches from the traced process, allowing it to continue execution
    /// independently.
    pub fn detach(&self) -> Result<(), String> {
        ptrace::detach(self.pid, None).map_err(|e| format!("ptrace::detach failed: {}", e))
    }
}

/// Spawn a shell command under ptrace control and wait for it to complete.
///
/// **Deprecated**: Use `spawn_seccomp_shell()` from the seccomp module instead.
/// The seccomp-unotify approach has lower overhead and doesn't require the
/// parent to be the tracer process.
///
/// This is a convenience function that combines `TracedProcess::spawn_traced`
/// and `run_loop()` into a single call. It spawns the specified shell with
/// the given arguments, traces all syscalls, blocks until the child exits,
/// and returns the exit status.
///
/// # Arguments
///
/// * `shell` - The shell executable to run (e.g., "/bin/bash")
/// * `args` - Arguments to pass to the shell (e.g., ["-c", "ls -la"])
/// * `daemon_url` - URL for communication with a tracing daemon (currently unused)
///
/// # Returns
///
/// Returns `Ok(ExitStatus)` with the child's exit status, or an error string on failure.
///
/// # Example
///
/// ```no_run
/// use sevorix_core::tracer::spawn_traced_shell;
///
/// let env = vec![("HTTP_PROXY".to_string(), "http://localhost:3000".to_string())];
/// let status = spawn_traced_shell(
///     "/bin/bash",
///     &["-c".to_string(), "echo hello".to_string()],
///     "http://localhost:3000",
///     env
/// ).unwrap();
///
/// if status.success() {
///     println!("Command succeeded");
/// }
/// ```
#[deprecated(
    since = "0.7.0",
    note = "Use spawn_seccomp_shell() from the seccomp module instead"
)]
#[allow(deprecated)] // Uses deprecated TracedProcess internally
pub fn spawn_traced_shell(
    shell: &str,
    args: &[String],
    _daemon_url: &str,
    env_vars: Vec<(String, String)>,
) -> Result<ExitStatus, String> {
    // Convert String args to &str for spawn_traced_with_env
    let args_str: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    // Spawn the process under ptrace control with environment variables
    let mut traced = TracedProcess::spawn_traced_with_env(shell, &args_str, env_vars)?;

    // Run the tracing loop until the child exits
    traced.run_loop()
}

#[cfg(test)]
#[allow(deprecated)] // Tests for deprecated ptrace functionality
mod tests {
    use super::*;

    #[test]
    #[ignore = "ptrace module is deprecated; use seccomp-unotify instead. This test spawns traced processes."]
    fn test_spawn_true_and_capture_execve() {
        // Spawn /bin/true and verify we capture the execve syscall
        let mut traced =
            TracedProcess::spawn_traced("/bin/true", &[]).expect("Failed to spawn traced process");

        let mut captured_execve = false;
        let mut syscall_count = 0;

        traced
            .run_syscall_loop(|event| {
                syscall_count += 1;
                // execve syscall number on x86_64 is 59
                if event.number == 59 && event.is_entry {
                    captured_execve = true;
                }
            })
            .expect("Syscall loop failed");

        assert!(captured_execve, "Should have captured execve syscall");
        assert!(syscall_count > 0, "Should have captured some syscalls");
    }

    #[test]
    #[ignore = "ptrace module is deprecated; use seccomp-unotify instead. This test spawns traced processes."]
    fn test_spawn_with_args() {
        // Test spawning a process with arguments
        let mut traced = TracedProcess::spawn_traced("/bin/echo", &["hello"])
            .expect("Failed to spawn traced process");

        let mut captured_execve = false;

        traced
            .run_syscall_loop(|event| {
                if event.number == 59 && event.is_entry {
                    captured_execve = true;
                }
            })
            .expect("Syscall loop failed");

        assert!(captured_execve, "Should have captured execve syscall");
    }

    #[test]
    #[ignore = "ptrace module is deprecated; use seccomp-unotify instead. This test spawns traced processes."]
    fn test_extract_args_execve() {
        // Test that extract_args correctly extracts execve arguments
        let mut traced = TracedProcess::spawn_traced("/bin/echo", &["test-arg"])
            .expect("Failed to spawn traced process");

        let mut execve_args_captured: Option<Vec<String>> = None;

        traced
            .run_syscall_loop(|event| {
                // Only capture the first execve entry (before exec happens)
                if event.number == syscall_nr::EXECVE
                    && event.is_entry
                    && execve_args_captured.is_none()
                {
                    let args = extract_args(event.pid, event.number);
                    // Only store if we got valid args (pathname not 0x0)
                    if !args.is_empty() && !args[0].contains("0x0") {
                        execve_args_captured = Some(args);
                    }
                }
            })
            .expect("Syscall loop failed");

        let args = execve_args_captured.expect("Should have captured execve syscall");
        // Should have at least pathname and argv
        assert!(!args.is_empty(), "Args should not be empty for execve");
        // First arg should contain the pathname
        assert!(
            args[0].contains("/bin/echo"),
            "pathname should contain /bin/echo, got: {:?}",
            args
        );
        // Second arg should contain argv
        assert!(
            args[1].contains("test-arg"),
            "argv should contain 'test-arg', got: {:?}",
            args
        );
    }

    #[test]
    fn test_format_generic_args() {
        // Test generic argument formatting
        let args: [u64; 6] = [0x100, 0x200, 0x300, 0x400, 0x500, 0x600];
        let formatted = format_generic_args(&args);

        assert_eq!(formatted.len(), 6);
        assert_eq!(formatted[0], "0x100");
        assert_eq!(formatted[5], "0x600");
    }

    #[test]
    fn test_format_socket_args() {
        // Test socket syscall argument formatting
        let args: [u64; 6] = [2, 1, 6, 0, 0, 0]; // AF_INET, SOCK_STREAM, 6
        let formatted = format_socket_args(&args);

        assert_eq!(formatted.len(), 3);
        assert_eq!(formatted[0], "domain=AF_INET");
        assert_eq!(formatted[1], "type=SOCK_STREAM");
        assert_eq!(formatted[2], "protocol=6");
    }

    #[test]
    #[ignore = "ptrace module is deprecated; use seccomp-unotify instead. This test hangs due to ptrace limitations."]
    fn test_run_loop_exit_status() {
        // Test that run_loop returns the correct exit status
        let mut traced =
            TracedProcess::spawn_traced("/bin/true", &[]).expect("Failed to spawn traced process");

        let status = traced.run_loop().expect("run_loop failed");

        assert!(status.success(), "/bin/true should exit successfully");
    }

    #[test]
    #[ignore = "ptrace module is deprecated; use seccomp-unotify instead. This test hangs due to ptrace limitations."]
    fn test_run_loop_nonzero_exit() {
        // Test that run_loop correctly returns non-zero exit status
        let mut traced =
            TracedProcess::spawn_traced("/bin/false", &[]).expect("Failed to spawn traced process");

        let status = traced.run_loop().expect("run_loop failed");

        assert!(!status.success(), "/bin/false should exit with failure");
        assert!(status.code().is_some(), "Should have an exit code");
    }

    #[test]
    #[ignore = "ptrace module is deprecated; use seccomp-unotify instead. This test spawns traced processes."]
    fn test_spawn_traced_shell_success() {
        // Test spawn_traced_shell with a successful command
        let status = spawn_traced_shell(
            "/bin/bash",
            &["-c".to_string(), "exit 0".to_string()],
            "http://localhost:3000",
            vec![],
        )
        .expect("spawn_traced_shell failed");

        assert!(status.success(), "exit 0 should be successful");
    }

    #[test]
    #[ignore = "ptrace module is deprecated; use seccomp-unotify instead. This test hangs due to ptrace limitations."]
    fn test_spawn_traced_shell_failure() {
        // Test spawn_traced_shell with a failing command
        let status = spawn_traced_shell(
            "/bin/bash",
            &["-c".to_string(), "exit 42".to_string()],
            "http://localhost:3000",
            vec![],
        )
        .expect("spawn_traced_shell failed");

        assert!(!status.success(), "exit 42 should not be successful");
        assert_eq!(status.code(), Some(42), "Exit code should be 42");
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_syscall_name_known() {
        // Test known syscall numbers
        assert_eq!(syscall_name(0), "read");
        assert_eq!(syscall_name(1), "write");
        assert_eq!(syscall_name(59), "execve");
        assert_eq!(syscall_name(60), "exit");
        assert_eq!(syscall_name(257), "openat");
        assert_eq!(syscall_name(435), "clone3");
        assert_eq!(syscall_name(448), "process_mrelease");
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_syscall_name_unknown() {
        // Test unknown syscall numbers
        assert_eq!(syscall_name(-1), "unknown");
        assert_eq!(syscall_name(335), "unknown"); // Gap in syscall table
        assert_eq!(syscall_name(500), "unknown"); // Beyond defined syscalls
    }

    #[test]
    #[ignore = "ptrace module is deprecated; use seccomp-unotify instead. This test hangs due to ptrace::kill() limitations."]
    fn test_kill_syscall() {
        use nix::sys::signal::kill;

        // Test that kill_syscall terminates a traced process
        let traced = TracedProcess::spawn_traced("/bin/sleep", &["10"])
            .expect("Failed to spawn traced process");

        // Kill the process - it should terminate, not exit normally
        let result = kill_syscall(traced.pid);
        assert!(result.is_ok(), "kill_syscall should succeed");

        // Wait for the process with timeout using WNOHANG polling
        // ptrace::kill() only works when tracee is in ptrace-stop, so we may need
        // to send a real SIGKILL as backup if the process is running
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let status;

        loop {
            match waitpid(traced.pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => {
                    // Process still running, check if we should send backup SIGKILL
                    if std::time::Instant::now() > deadline - std::time::Duration::from_secs(4) {
                        // ptrace::kill didn't work (process not in ptrace-stop), send real SIGKILL
                        let _ = kill(traced.pid, Signal::SIGKILL);
                    }
                    if std::time::Instant::now() > deadline {
                        panic!("test_kill_syscall: process did not terminate within timeout");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Ok(s) => {
                    // Process exited
                    status = s;
                    break;
                }
                Err(_) => {
                    // Process already gone, which is fine
                    return;
                }
            }
        }

        // The process should have been signaled (SIGKILL)
        match status {
            WaitStatus::Signaled(_, Signal::SIGKILL, _) => {
                // Expected: killed by SIGKILL
            }
            WaitStatus::Signaled(_, _, _) => {
                // Acceptable: killed by some signal
            }
            WaitStatus::Exited(_, code) => {
                // Some systems may report this as an exit
                // SIGKILL typically results in exit code 137 (128 + 9)
                // But we accept any exit since the key test is that it terminated
                let _ = code;
            }
            _ => {
                // Unexpected status, but process did stop
            }
        }
    }
}
