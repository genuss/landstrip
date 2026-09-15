#[cfg(target_os = "macos")]
pub fn sysv_sem_probe() -> i32 {
    struct Semaphore(libc::c_int);

    impl Drop for Semaphore {
        fn drop(&mut self) {
            unsafe { libc::semctl(self.0, 0, libc::IPC_RMID) };
        }
    }

    let result = (|| -> std::io::Result<()> {
        let id = unsafe { libc::semget(libc::IPC_PRIVATE, 1, libc::IPC_CREAT | 0o600) };
        if id == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let sem = Semaphore(id);
        if unsafe { libc::semctl(sem.0, 0, libc::SETVAL, 1 as libc::c_int) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        for (operation, expected) in [(-1, 0), (1, 1)] {
            let mut op = libc::sembuf {
                sem_num: 0,
                sem_op: operation,
                sem_flg: (libc::SEM_UNDO | libc::IPC_NOWAIT) as libc::c_short,
            };
            if unsafe { libc::semop(sem.0, &raw mut op, 1) } == -1 {
                return Err(std::io::Error::last_os_error());
            }
            let value = unsafe { libc::semctl(sem.0, 0, libc::GETVAL) };
            if value == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if value != expected {
                return Err(std::io::Error::other("unexpected semaphore value"));
            }
        }
        if unsafe { libc::semctl(sem.0, 0, libc::IPC_RMID) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        std::mem::forget(sem);
        Ok(())
    })();
    match result {
        Ok(()) => {
            println!("semaphore round-trip ok");
            0
        }
        Err(error) => {
            eprintln!("System V semaphore probe: {error}");
            1
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn sysv_sem_probe() -> i32 {
    2
}
