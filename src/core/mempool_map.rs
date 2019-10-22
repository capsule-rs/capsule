use crate::dpdk::{Mempool, SocketId};
use crate::ffi;
use crate::Result;
use failure::Fail;
use std::collections::HashMap;

/// Error indicating the `Mempool` is not found.
#[derive(Debug, Fail)]
#[fail(display = "Mempool for {:?} not found.", _0)]
pub struct MempoolNotFound(SocketId);

/// A specialized hash map of `SocketId` to `Mempool`.
pub struct MempoolMap {
    inner: HashMap<SocketId, Mempool>,
}

impl MempoolMap {
    /// Creates a `MempoolMap` for all the sockets listed.
    pub fn new(capacity: usize, cache_size: usize, sockets: &[SocketId]) -> Result<MempoolMap> {
        let mut inner = HashMap::new();

        for &socket_id in sockets.iter() {
            let pool = Mempool::new(capacity, cache_size, socket_id)?;
            info!("created {}.", pool.name());
            debug!(?pool);

            inner.insert(socket_id, pool);
        }

        Ok(MempoolMap { inner })
    }

    /// Borrows the individual mempool in the hash map mutably and constructs
    /// a new hash map of the borrows. The new hash map can be shared without
    /// any smart or unsafe pointers.
    pub fn borrow_mut(&mut self) -> MempoolMap2 {
        let inner = self.inner.iter_mut().map(|(&k, v)| (k, v)).collect();
        MempoolMap2 { inner }
    }
}

/// A mutable borrow of `MempoolMap` so we can share the mempools mutably
/// without smart or unsafe pointers.
pub struct MempoolMap2<'a> {
    inner: HashMap<SocketId, &'a mut Mempool>,
}

impl<'a> MempoolMap2<'a> {
    /// Returns a mutable reference to the raw mempool corresponding to the
    /// socket id.
    ///
    /// # Errors
    ///
    /// If the value is not found, `MempoolNotFound` is returned.
    pub fn get_raw(&mut self, socket_id: SocketId) -> Result<&mut ffi::rte_mempool> {
        self.inner
            .get_mut(&socket_id)
            .ok_or_else(|| MempoolNotFound(socket_id).into())
            .map(|pool| pool.raw_mut())
    }
}

impl<'a> Default for MempoolMap2<'a> {
    fn default() -> MempoolMap2<'a> {
        MempoolMap2 {
            inner: HashMap::new(),
        }
    }
}
