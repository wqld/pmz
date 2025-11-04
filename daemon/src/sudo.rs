use std::process::{Command, Stdio};

use PrivilegeLevel::*;
use anyhow::Result;
use tracing::debug;

#[derive(Debug)]
pub enum PrivilegeLevel {
    Root,
    User,
}

impl PrivilegeLevel {
    fn current() -> Self {
        let uid = unsafe { libc::getuid() };
        let euid = unsafe { libc::geteuid() };

        match (uid, euid) {
            (0, 0) => Root,
            (_, _) => User,
        }
    }

    fn run_as_root() -> Result<()> {
        let args: Vec<_> = std::env::args().collect();

        let mut command = Command::new("sudo");

        let mut child = command
            .arg("-E")
            .arg("--preserve-env=PATH")
            .args(&args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;

        let ecode = child.wait()?;

        if ecode.success() {
            std::process::exit(0);
        } else {
            std::process::exit(ecode.code().unwrap_or(1));
        }
    }

    pub fn escalate_if_needed() -> Result<()> {
        let current = Self::current();

        debug!("Running as {:?}", current);

        match current {
            Root => Ok(()),
            _ => Self::run_as_root(),
        }
    }
}
