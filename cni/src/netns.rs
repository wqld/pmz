use anyhow::Result;
use log::{debug, error};
use nix::sched::{CloneFlags, setns};
use std::{os::fd::OwnedFd, sync::Arc};

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

    pub fn run<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        let _guard = self.enter()?;
        f()
    }

    fn enter(&self) -> Result<NamespaceGuard> {
        debug!("Try to use 'setns'");
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
        debug!("Drop The Namespace!");
        if let Err(e) = setns(&self.current, CloneFlags::CLONE_NEWNET) {
            error!("Failed to restore original network namespace: {e}");
        }
    }
}
