use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

pub(super) const PROBE_ARG: &str = "--test-terminal";

struct Pty {
    _master: File,
    slave: File,
    path: OsString,
}

impl Pty {
    fn new() -> io::Result<Self> {
        use std::os::unix::ffi::OsStrExt;

        let mut master = -1;
        let mut slave = -1;
        let mut name = [0; libc::PATH_MAX as usize];
        let rc = unsafe {
            libc::openpty(
                &raw mut master,
                &raw mut slave,
                name.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) };
        Ok(Self {
            _master: unsafe { File::from_raw_fd(master) },
            slave: unsafe { File::from_raw_fd(slave) },
            path: std::ffi::OsStr::from_bytes(name.to_bytes()).to_owned(),
        })
    }
}

fn attributes(fd: RawFd) -> io::Result<libc::termios> {
    let mut value = std::mem::MaybeUninit::uninit();
    if unsafe { libc::tcgetattr(fd, value.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { value.assume_init() })
}

fn set_attributes(fd: RawFd, value: &libc::termios) -> io::Result<()> {
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn same_attributes(actual: &libc::termios, expected: &libc::termios) -> bool {
    actual.c_iflag == expected.c_iflag
        && actual.c_oflag == expected.c_oflag
        && actual.c_cflag == expected.c_cflag
        && actual.c_lflag == expected.c_lflag
        && actual.c_cc == expected.c_cc
        && actual.c_ispeed == expected.c_ispeed
        && actual.c_ospeed == expected.c_ospeed
}

fn raw_mode_round_trip(fd: RawFd) -> io::Result<()> {
    let original = attributes(fd)?;
    let mut raw = original;
    unsafe { libc::cfmakeraw(&raw mut raw) };
    set_attributes(fd, &raw)?;
    let actual = attributes(fd);
    set_attributes(fd, &original)?;
    if !same_attributes(&actual?, &raw) || !same_attributes(&attributes(fd)?, &original) {
        return Err(io::Error::other("terminal attributes did not round-trip"));
    }
    Ok(())
}

pub(super) fn probe(args: Vec<OsString>) -> i32 {
    let result = (|| -> io::Result<()> {
        let fd: RawFd = args[0].to_str().unwrap().parse().unwrap();
        if fd >= 0 {
            raw_mode_round_trip(fd)?;
        }
        let terminal = OpenOptions::new().read(true).write(true).open(&args[1])?;
        let fd = terminal.as_raw_fd();
        let result = attributes(fd).and_then(|original| set_attributes(fd, &original));
        if result.err().and_then(|error| error.raw_os_error()) != Some(libc::EPERM) {
            return Err(io::Error::other(
                "unattached terminal ioctl was not denied with EPERM",
            ));
        }
        if std::fs::write(&args[2], b"must stay denied").is_ok() {
            return Err(io::Error::other("terminal grant bypassed write policy"));
        }
        Ok(())
    })();
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("terminal probe: {error}");
            1
        }
    }
}

pub(super) fn run(mut command: Command, fd: RawFd, denied: &Path) -> Result<Output, String> {
    let run = || -> io::Result<Output> {
        let attached = Pty::new()?;
        let unrelated = Pty::new()?;
        raw_mode_round_trip(unrelated.slave.as_raw_fd())?;
        let original = attributes(attached.slave.as_raw_fd())?;
        if fd == 3 {
            let source = attached.slave.as_raw_fd();
            unsafe {
                command.pre_exec(move || {
                    if libc::dup2(source, 3) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        command
            .arg(std::env::current_exe()?)
            .arg(PROBE_ARG)
            .arg(fd.to_string())
            .arg(&unrelated.path)
            .arg(denied)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match fd {
            0 => {
                command.stdin(attached.slave.try_clone()?);
            }
            1 => {
                command.stdout(attached.slave.try_clone()?);
            }
            2 => {
                command.stderr(attached.slave.try_clone()?);
            }
            _ => {}
        }
        let mut child = command.spawn()?;
        drop(command);
        let deadline = Instant::now() + Duration::from_secs(10);
        let waited = loop {
            match child.try_wait() {
                Ok(Some(_)) => break Ok(()),
                Err(error) => break Err(error),
                Ok(None) if Instant::now() >= deadline => {
                    break Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "terminal probe timed out",
                    ));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            }
        };
        if waited.is_err() {
            super::stop(&mut child);
        }
        let output = child.wait_with_output();
        let restored = attributes(attached.slave.as_raw_fd());
        set_attributes(attached.slave.as_raw_fd(), &original)?;
        waited?;
        let output = output?;
        if output.status.success() && !same_attributes(&restored?, &original) {
            return Err(io::Error::other("terminal mode was not restored"));
        }
        Ok(output)
    };
    run().map_err(|error| format!("terminal fd {fd}: {error}"))
}
