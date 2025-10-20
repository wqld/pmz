use anyhow::Result;
use nix::sched::{CloneFlags, setns};
use std::{os::fd::OwnedFd, sync::Arc};
use tracing::{error, instrument};

#[derive(Debug)]
struct NetnsInner {
    current: Arc<OwnedFd>,
    target: OwnedFd,
}
#[derive(Clone, Debug)]
pub struct InpodNetns {
    inner: Arc<NetnsInner>,
}

impl InpodNetns {
    pub fn new(current: Arc<OwnedFd>, target: OwnedFd) -> Self {
        Self {
            inner: Arc::new(NetnsInner { current, target }),
        }
    }

    #[instrument(name = "run_in_ns", skip_all, level = "debug", err)]
    pub fn run<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        let _guard = self.enter()?;
        f()
    }

    fn enter(&self) -> Result<NamespaceGuard> {
        setns(&self.inner.target, CloneFlags::CLONE_NEWNET)
            .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;

        Ok(NamespaceGuard {
            current: self.inner.current.clone(),
        })
    }
}

struct NamespaceGuard {
    current: Arc<OwnedFd>,
}

impl Drop for NamespaceGuard {
    fn drop(&mut self) {
        if let Err(e) = setns(&self.current, CloneFlags::CLONE_NEWNET) {
            error!(error = ?e, "Failed to restore original network namespace");
        }
    }
}
