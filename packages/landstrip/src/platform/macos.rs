// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! macOS Seatbelt (SBPL) sandbox platform.

use super::unix::close_inherited_fds;
use crate::error::{Error, Mechanism};
use crate::policy::{
    AccessPolicy, NetworkAccess, ReadAccess, UnixSocketAccess, WriteAllowPattern, byte_in_class,
};
use crate::trap_fd::TrapFd;
use anyhow::Result;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt::{self, Write};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::ptr;

const SBPL_PROFILE_FLAGS: u64 = 0;
const SANDBOX_FILTER_NONE: libc::c_int = 0;

pub(crate) fn execute(
    policy: &AccessPolicy,
    tool: &OsStr,
    args: &[OsString],
    trap_fd: Option<&TrapFd>,
    inherited_fds: &[std::os::fd::RawFd],
) -> Result<i32> {
    let terminals = inherited_terminal_paths(inherited_fds).map_err(seatbelt_error)?;
    let profile = render_profile(policy, &terminals).map_err(seatbelt_error)?;
    apply_profile(&profile)?;
    close_inherited_fds(trap_fd.map(AsRawFd::as_raw_fd).as_slice(), inherited_fds)
        .map_err(seatbelt_error)?;
    let error = Command::new(tool).args(args).exec();
    Err(Error::launch(tool, error).into())
}

pub(crate) fn doctor() -> Result<()> {
    let operation = CString::new("file-read-data").map_err(seatbelt_error)?;
    let result =
        unsafe { ffi::sandbox_check(libc::getpid(), operation.as_ptr(), SANDBOX_FILTER_NONE) };
    if result < 0 {
        return Err(seatbelt_error(io::Error::last_os_error()));
    }
    Ok(())
}

fn seatbelt_error(source: impl Into<crate::error::Cause>) -> anyhow::Error {
    Error::sandbox_setup(Mechanism::Seatbelt, source).into()
}

fn apply_profile(profile: &str) -> Result<()> {
    let profile = CString::new(profile).map_err(|source| {
        seatbelt_error(format!(
            "profile: interior nul at offset {}",
            source.nul_position()
        ))
    })?;
    let mut errorbuf = ptr::null_mut();

    // SAFETY: profile is a live NULL-terminated C string and errorbuf points to writable
    // storage through a raw out pointer.
    let rc = unsafe { ffi::sandbox_init(profile.as_ptr(), SBPL_PROFILE_FLAGS, &raw mut errorbuf) };
    if rc == 0 {
        Ok(())
    } else {
        Err(seatbelt_error(take_sandbox_error(errorbuf)))
    }
}

fn inherited_terminal_paths(inherited_fds: &[RawFd]) -> io::Result<Vec<String>> {
    let mut terminals = Vec::new();
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO]
        .into_iter()
        .chain(inherited_fds.iter().copied())
    {
        if let Some(path) = terminal_path(fd)? {
            terminals.push(path);
        }
    }
    terminals.sort_unstable();
    terminals.dedup();
    Ok(terminals)
}

fn terminal_path(fd: RawFd) -> io::Result<Option<String>> {
    let mut buffer = [0; libc::PATH_MAX as usize];
    let rc = unsafe { libc::ttyname_r(fd, buffer.as_mut_ptr(), buffer.len()) };
    match rc {
        0 => {
            let path = unsafe { CStr::from_ptr(buffer.as_ptr()) };
            let path = path
                .to_str()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            Ok(Some(path.to_owned()))
        }
        libc::ENOTTY | libc::EBADF => Ok(None),
        errno => Err(io::Error::from_raw_os_error(errno)),
    }
}

fn render_profile(policy: &AccessPolicy, terminals: &[String]) -> Result<String> {
    let mut sb = String::new();
    writeln!(sb, "(version 1)")?;
    writeln!(sb, "(deny default)")?;

    render_process_rules(&mut sb)?;
    render_mach_rules(&mut sb)?;
    writeln!(sb, "(allow ipc-sysv-sem)")?;
    writeln!(sb, "(allow ipc-posix-sem)")?;
    render_terminal_rules(&mut sb, terminals)?;
    render_write_rules(
        &mut sb,
        &policy.write_roots,
        &policy.write_allowed_patterns,
        &policy.write_denied_roots,
        &policy.write_denied_patterns,
    )?;
    render_read_rules(
        &mut sb,
        &policy.read_access,
        &policy.read_denied_roots,
        &policy.read_symlinks,
    )?;
    render_network_rules(&mut sb, &policy.network_access)?;

    Ok(sb)
}

fn render_process_rules(sb: &mut String) -> fmt::Result {
    writeln!(sb, "(allow process-exec)")?;
    // Seatbelt blocks the setuid system ps binary unless it executes outside the sandbox.
    writeln!(
        sb,
        "(allow process-exec (path \"/bin/ps\") (with no-sandbox))",
    )?;
    writeln!(sb, "(allow process-fork)")?;
    writeln!(sb, "(allow process-info* (target same-sandbox))")?;
    writeln!(sb, "(allow signal (target same-sandbox))")?;
    writeln!(sb, "(allow sysctl-read)")
}

/// Default Mach services, matching the Anthropic sandbox-runtime (srt) base
/// profile plus `SecurityServer` and trustd for Keychain / TLS trust.
fn render_mach_rules(sb: &mut String) -> fmt::Result {
    writeln!(sb, "(allow mach-lookup")?;
    writeln!(sb, "  (global-name \"com.apple.SecurityServer\")")?;
    writeln!(sb, "  (global-name \"com.apple.trustd.agent\")")?;
    writeln!(sb, "  (global-name \"com.apple.audio.systemsoundserver\")")?;
    writeln!(sb, "  (global-name \"com.apple.bsd.dirhelper\")")?;
    writeln!(
        sb,
        "  (global-name \"com.apple.coreservices.launchservicesd\")"
    )?;
    writeln!(
        sb,
        "  (global-name \"com.apple.distributed_notifications@Uv3\")"
    )?;
    writeln!(sb, "  (global-name \"com.apple.FSEvents\")")?;
    writeln!(sb, "  (global-name \"com.apple.FontObjectsServer\")")?;
    writeln!(sb, "  (global-name \"com.apple.fonts\")")?;
    writeln!(sb, "  (global-name \"com.apple.logd\")")?;
    writeln!(sb, "  (global-name \"com.apple.lsd.mapdb\")")?;
    writeln!(sb, "  (global-name \"com.apple.pasteboard.1\")")?;
    writeln!(sb, "  (global-name \"com.apple.PowerManagement.control\")")?;
    writeln!(sb, "  (global-name \"com.apple.securityd.xpc\")")?;
    // apple/container CLI talks to its daemons over XPC.
    writeln!(sb, "  (global-name-prefix \"com.apple.container.\")")?;
    writeln!(sb, "  (global-name \"com.apple.system.logger\")")?;
    writeln!(
        sb,
        "  (global-name \"com.apple.system.notification_center\")"
    )?;
    writeln!(
        sb,
        "  (global-name \"com.apple.system.opendirectoryd.libinfo\")"
    )?;
    writeln!(
        sb,
        "  (global-name \"com.apple.system.opendirectoryd.membership\")"
    )?;
    writeln!(sb, ")")?;
    writeln!(
        sb,
        "(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))"
    )?;
    writeln!(sb, "(allow system-socket (socket-domain AF_ROUTE))")
}

fn render_terminal_rules(sb: &mut String, terminals: &[String]) -> fmt::Result {
    for terminal in terminals {
        let escaped = escape_sbpl_literal(terminal);
        writeln!(sb, "(allow file-ioctl (literal \"{escaped}\"))")?;
    }
    Ok(())
}

fn glob_to_sbpl_regex(pattern: &str) -> String {
    let mut regex = String::from("^");
    let mut rest = pattern;

    while !rest.is_empty() {
        if let Some(tail) = rest.strip_prefix("**/") {
            regex.push_str("(.*/)?");
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix("**") {
            regex.push_str(".*");
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix('*') {
            regex.push_str("[^/]*");
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix('?') {
            regex.push_str("[^/]");
            rest = tail;
        } else if rest.starts_with('[') {
            if let Some(offset) = rest[1..].find(']') {
                let end = 1 + offset;
                regex.push_str(&rest[..=end]);
                rest = &rest[end + 1..];
            } else {
                regex.push_str("\\[");
                rest = &rest[1..];
            }
        } else {
            let mut chars = rest.chars();
            let Some(ch) = chars.next() else {
                break;
            };
            match ch {
                '.' | '(' | ')' | '{' | '}' | '+' | '|' | '^' | '$' | '\\' => {
                    regex.push('\\');
                    regex.push(ch);
                }
                _ => regex.push(ch),
            }
            rest = chars.as_str();
        }
    }

    regex.push('$');
    regex
}

pub(super) fn validate_write_patterns(policy: &AccessPolicy) -> Result<()> {
    for pattern in &policy.write_allowed_patterns {
        write_allow_regex(pattern)?;
    }
    Ok(())
}

fn write_allow_regex(pattern: &WriteAllowPattern) -> Result<String, Error> {
    let prefix = pattern
        .prefix
        .to_str()
        .ok_or(Error::PolicyWriteGlobUnsupported)?;
    if prefix
        .chars()
        .chain(pattern.glob.chars())
        .any(char::is_control)
    {
        return Err(Error::PolicyWriteGlobUnsupported);
    }

    let mut regex = String::from("^");
    for ch in prefix.chars() {
        push_regex_char(&mut regex, ch);
    }
    if !prefix.ends_with('/') {
        regex.push('/');
    }
    let mut rest = pattern.glob.as_str();
    while !rest.is_empty() {
        if let Some(tail) = rest.strip_prefix("**/") {
            regex.push_str("(.*/)?");
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix("**") {
            regex.push_str(".*");
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix('*') {
            regex.push_str("[^/]*");
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix('?') {
            regex.push_str("[^/]");
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix('[')
            && let Some(end) = tail.find(']')
        {
            regex.push_str(&write_allow_class(&tail[..end])?);
            rest = &tail[end + 1..];
        } else {
            let mut chars = rest.chars();
            if let Some(ch) = chars.next() {
                push_regex_char(&mut regex, ch);
            }
            rest = chars.as_str();
        }
    }
    regex.push_str("(/.*)?$");
    Ok(regex)
}

fn write_allow_class(class: &str) -> Result<String, Error> {
    if !class.is_ascii() {
        return Err(Error::PolicyWriteGlobUnsupported);
    }
    let mut alternatives = Vec::new();
    for byte in 1..=127 {
        if byte != b'/' && byte_in_class(byte, class.as_bytes()) {
            let mut literal = String::new();
            push_regex_char(&mut literal, char::from(byte));
            alternatives.push(literal);
        }
    }
    if alternatives.is_empty() {
        return Err(Error::PolicyWriteGlobUnsupported);
    }
    Ok(format!("({})", alternatives.join("|")))
}

fn push_regex_char(regex: &mut String, ch: char) {
    if matches!(
        ch,
        '.' | '(' | ')' | '{' | '}' | '+' | '|' | '^' | '$' | '\\' | '[' | ']' | '*' | '?'
    ) {
        regex.push('\\');
    }
    regex.push(ch);
}

fn render_write_rules(
    sb: &mut String,
    write_roots: &[PathBuf],
    write_allowed_patterns: &[WriteAllowPattern],
    write_denied_roots: &[PathBuf],
    write_denied_patterns: &[String],
) -> Result<()> {
    for root in write_roots {
        let escaped = escape_sbpl_literal(&root.to_string_lossy());
        writeln!(sb, "(allow file-write* (subpath \"{escaped}\"))")?;
    }

    for pattern in write_allowed_patterns {
        let regex = write_allow_regex(pattern)?;
        let escaped = escape_sbpl_literal(&regex);
        writeln!(sb, "(allow file-write* (regex \"{escaped}\"))")?;
    }

    // Deny rules follow the allow rules so SBPL's last-match-wins precedence
    // subtracts the denied subtrees from the granted write roots.
    for root in write_denied_roots {
        let escaped = escape_sbpl_literal(&root.to_string_lossy());
        writeln!(sb, "(deny file-write* (subpath \"{escaped}\"))")?;
    }

    // Regex rules are evaluated at syscall time, so unlike expand_glob_path
    // they also cover paths created after sandbox_init.
    for pattern in write_denied_patterns {
        let regex = glob_to_sbpl_regex(pattern);
        let escaped = escape_sbpl_literal(&regex);
        writeln!(sb, "(deny file-write* (regex \"{escaped}\"))")?;
    }

    Ok(())
}

fn render_read_rules(
    sb: &mut String,
    read_access: &ReadAccess,
    read_denied_roots: &[PathBuf],
    read_symlinks: &[PathBuf],
) -> fmt::Result {
    match read_access {
        ReadAccess::Unrestricted => sb.push_str("(allow file-read*)\n"),
        ReadAccess::AllowRoots(roots) => {
            writeln!(sb, "(deny file-read*)")?;
            writeln!(sb, "(allow file-read* (literal \"/\"))")?;
            for root in roots {
                let escaped = escape_sbpl_literal(&root.to_string_lossy());
                writeln!(sb, "(allow file-read* (subpath \"{escaped}\"))")?;
            }
            render_parent_dir_rules(sb, roots)?;

            render_symlink_metadata_rules(sb, read_symlinks)?;

            // Deny rules follow the allow rules so SBPL's last-match-wins
            // precedence subtracts the denied subtrees from the read roots.
            for root in read_denied_roots {
                let escaped = escape_sbpl_literal(&root.to_string_lossy());
                writeln!(sb, "(deny file-read* (subpath \"{escaped}\"))")?;
            }
        }
    }

    Ok(())
}

fn render_parent_dir_rules(sb: &mut String, roots: &[PathBuf]) -> fmt::Result {
    let mut ancestors: Vec<PathBuf> = Vec::new();
    for root in roots {
        let mut current = root.as_path();
        while let Some(parent) = current.parent() {
            if parent.as_os_str().is_empty() {
                break;
            }
            ancestors.push(parent.to_path_buf());
            current = parent;
        }
    }
    ancestors.sort_unstable();
    ancestors.dedup();
    for ancestor in &ancestors {
        let escaped = escape_sbpl_literal(&ancestor.to_string_lossy());
        writeln!(sb, "(allow file-read* (literal \"{escaped}\"))")?;
    }
    Ok(())
}

/// Allow `readlink` on the lexical symlink inodes the read scan skipped.
///
/// Mirrors Apple's system.sb: `readlink` only permits resolution; the target
/// is still gated by the existing allow/deny rules, so this grants no new read
/// access.
fn render_symlink_metadata_rules(sb: &mut String, symlinks: &[PathBuf]) -> fmt::Result {
    if symlinks.is_empty() {
        return Ok(());
    }
    sb.push_str("(allow file-read-metadata");
    for sym in symlinks {
        let escaped = escape_sbpl_literal(&sym.to_string_lossy());
        write!(sb, "\n  (literal \"{escaped}\")")?;
    }
    sb.push_str(")\n");
    Ok(())
}

fn render_network_rules(sb: &mut String, network: &NetworkAccess) -> fmt::Result {
    if network.is_unrestricted() {
        sb.push_str("(allow network*)\n");
        return Ok(());
    }

    // AF_UNIX socket creation stays allowed regardless of the socket policy.
    sb.push_str("(allow system-socket (socket-domain AF_UNIX))\n");

    // Seatbelt accepts only `*` or `localhost` as the host token in an IP
    // endpoint filter. `localhost` permits IPv4 and IPv6 loopback connections,
    // matching the macOS Anthropic Sandbox Runtime behavior. On some hosts it
    // also matches addresses assigned to other local interfaces; Seatbelt
    // cannot express a stricter loopback-only rule.
    sb.push_str("(deny network-outbound)\n");
    for port in network.connect_tcp_ports() {
        writeln!(
            sb,
            "(allow network-outbound (remote tcp \"localhost:{port}\"))"
        )?;
    }

    if network.allows_local_binding() {
        // allowLocalBinding also grants host-local UDP on Seatbelt. Match the
        // destination for outbound traffic: a local/source filter would allow
        // remote egress from a locally bound socket.
        for protocol in ["tcp", "udp"] {
            writeln!(
                sb,
                "(allow network-outbound (remote {protocol} \"localhost:*\"))"
            )?;
            writeln!(
                sb,
                "(allow network-bind (local {protocol} \"localhost:*\"))"
            )?;
            writeln!(
                sb,
                "(allow network-inbound (local {protocol} \"localhost:*\"))"
            )?;
        }
    }

    match network.unix_socket_access() {
        UnixSocketAccess::Unrestricted => {
            sb.push_str("(allow network-outbound (remote unix-socket))\n");
            sb.push_str("(allow network-bind (local unix-socket))\n");
        }
        UnixSocketAccess::AllowPaths(paths) => {
            for path in paths {
                let escaped = escape_sbpl_literal(&path.to_string_lossy());
                writeln!(
                    sb,
                    "(allow network-outbound (remote unix-socket (subpath \"{escaped}\")))"
                )?;
                writeln!(
                    sb,
                    "(allow network-bind (local unix-socket (subpath \"{escaped}\")))"
                )?;
            }
        }
        UnixSocketAccess::Denied => {}
    }

    Ok(())
}

fn escape_sbpl_literal(path: &str) -> String {
    let mut escaped = String::with_capacity(path.len());
    for ch in path.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn take_sandbox_error(errorbuf: *mut libc::c_char) -> String {
    if errorbuf.is_null() {
        return "sandbox_init failed without an error message".to_string();
    }

    let message = unsafe { CStr::from_ptr(errorbuf) }
        .to_string_lossy()
        .into_owned();
    unsafe { ffi::sandbox_free_error(errorbuf) };
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(prefix: &str, glob: &str) -> WriteAllowPattern {
        WriteAllowPattern {
            prefix: PathBuf::from(prefix),
            glob: glob.to_owned(),
        }
    }

    #[test]
    fn write_allow_regex_anchors_roots_and_descendants() -> Result<()> {
        assert_eq!(
            write_allow_regex(&pattern("/projects", "**/.git"))?,
            r"^/projects/(.*/)?\.git(/.*)?$"
        );
        assert_eq!(
            write_allow_regex(&pattern("/", "repo*/match?"))?,
            r"^/repo[^/]*/match[^/](/.*)?$"
        );
        Ok(())
    }

    #[test]
    fn write_allow_regex_quotes_literal_prefixes_and_glob_literals() -> Result<()> {
        assert_eq!(
            write_allow_regex(&pattern(r"/repo[1]*?", r#"**/a(b)+{c}$^|d\e"f]"#))?,
            r#"^/repo\[1\]\*\?/(.*/)?a\(b\)\+\{c\}\$\^\|d\\e"f\](/.*)?$"#
        );
        assert_eq!(
            write_allow_regex(&pattern("/projects", "release["))?,
            r"^/projects/release\[(/.*)?$"
        );
        Ok(())
    }

    #[test]
    fn write_allow_classes_use_glob_not_regex_semantics() -> Result<()> {
        assert_eq!(write_allow_class("0-2")?, "(0|1|2)");
        assert_eq!(write_allow_class("^a")?, r"(\^|a)");
        assert_eq!(write_allow_class("!a")?, "(!|a)");
        assert_eq!(write_allow_class("-")?, "(-)");
        assert_eq!(write_allow_class(".0")?, "(\\.|0)");
        assert!(write_allow_class("").is_err());
        assert!(write_allow_class("z-a").is_err());
        assert!(write_allow_class("é").is_err());
        assert!(write_allow_regex(&pattern("/projects", "*\n")).is_err());
        Ok(())
    }

    #[test]
    fn native_compiler_accepts_escaped_write_rules() -> Result<()> {
        for glob in [
            "**/.git",
            r#"**/repo"quoted"#,
            r"**/repo\backslash",
            r#"**/repo") (allow default) ("#,
            "**/repo[-]",
            r"**/repo[\]",
            "**/repo[.]",
        ] {
            let mut profile = String::from("(version 1)\n(deny default)\n");
            render_write_rules(
                &mut profile,
                &[],
                &[pattern("/projects", glob)],
                &[],
                &[r#"/projects/**/private"quoted\file"#.to_owned()],
            )?;
            let profile = CString::new(profile)?;
            let mut error = ptr::null_mut();
            let compiled = unsafe {
                ffi::sandbox_compile_string(profile.as_ptr(), ptr::null_mut(), &raw mut error)
            };
            if compiled.is_null() {
                return Err(seatbelt_error(take_sandbox_error(error)));
            }
            unsafe { ffi::sandbox_free_profile(compiled) };
            if !error.is_null() {
                unsafe { ffi::sandbox_free_error(error) };
            }
        }
        Ok(())
    }

    #[test]
    fn write_denials_follow_both_kinds_of_grants() -> Result<()> {
        let mut profile = String::new();
        render_write_rules(
            &mut profile,
            &[PathBuf::from("/concrete")],
            &[pattern("/projects", "**/.git")],
            &[PathBuf::from("/projects/private")],
            &["/projects/**/.env".to_owned()],
        )?;
        let lines: Vec<_> = profile.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].starts_with("(allow file-write* (subpath"));
        assert!(lines[1].starts_with("(allow file-write* (regex"));
        assert!(lines[2].starts_with("(deny file-write* (subpath"));
        assert!(lines[3].starts_with("(deny file-write* (regex"));
        Ok(())
    }
}

mod ffi {
    use libc::{c_char, c_int};

    #[link(name = "sandbox")]
    unsafe extern "C" {
        pub(super) fn sandbox_init(
            profile: *const c_char,
            flags: u64,
            errorbuf: *mut *mut c_char,
        ) -> c_int;
        pub(super) fn sandbox_free_error(errorbuf: *mut c_char);
        #[cfg(test)]
        pub(super) fn sandbox_compile_string(
            profile: *const c_char,
            parameters: *mut libc::c_void,
            errorbuf: *mut *mut c_char,
        ) -> *mut libc::c_void;
        #[cfg(test)]
        pub(super) fn sandbox_free_profile(profile: *mut libc::c_void);
        pub(super) fn sandbox_check(
            pid: libc::pid_t,
            operation: *const c_char,
            filter_type: c_int,
            ...
        ) -> c_int;
    }
}
