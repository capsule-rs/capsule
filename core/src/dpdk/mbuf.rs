/*
* Copyright 2019 Comcast Cable Communications Management, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* SPDX-License-Identifier: Apache-2.0
*/

use super::MEMPOOL;
use crate::dpdk::{DpdkError, MempoolError};
use crate::ffi::{self, ToResult};
use crate::packets::{Internal, Packet};
use crate::{ensure, trace};
use failure::{Fail, Fallible};
use std::fmt;
use std::mem;
use std::os::raw;
use std::ptr::{self, NonNull};
use std::slice;

/// A trait for returning the size of a type in bytes.
///
/// Size of the structs are used for bound checks when reading and writing
/// packets.
///
///
/// # Derivable
///
/// The `SizeOf` trait can be used with `#[derive]` and defaults to
/// `std::mem::size_of::<Self>()`.
///
/// ```
/// #[derive(SizeOf)]
/// pub struct Ipv4Header {
///     ...
/// }
/// ```
pub trait SizeOf {
    /// Returns the size of a type in bytes.
    fn size_of() -> usize;
}

impl SizeOf for () {
    fn size_of() -> usize {
        std::mem::size_of::<()>()
    }
}

impl SizeOf for u8 {
    fn size_of() -> usize {
        std::mem::size_of::<u8>()
    }
}

impl SizeOf for [u8; 2] {
    fn size_of() -> usize {
        std::mem::size_of::<[u8; 2]>()
    }
}

impl SizeOf for [u8; 16] {
    fn size_of() -> usize {
        std::mem::size_of::<[u8; 16]>()
    }
}

impl SizeOf for ::std::net::Ipv6Addr {
    fn size_of() -> usize {
        std::mem::size_of::<std::net::Ipv6Addr>()
    }
}

/// Error indicating buffer access failures.
#[derive(Debug, Fail)]
pub(crate) enum BufferError {
    /// The offset exceeds the buffer length.
    #[fail(display = "Offset {} exceeds the buffer length {}.", _0, _1)]
    BadOffset(usize, usize),

    /// The buffer is not resized.
    #[fail(display = "Buffer is not resized.")]
    NotResized,

    /// The struct size exceeds the remaining buffer length.
    #[fail(
        display = "Struct size {} exceeds the remaining buffer length {}.",
        _0, _1
    )]
    OutOfBuffer(usize, usize),
}

/// A DPDK message buffer that carries the network packet.
///
/// # Remarks
///
/// Multi-segment Mbuf is not supported. It's the application's responsibilty
/// to ensure that the ethernet device's MTU is less than the default size
/// of a single Mbuf segment (`RTE_MBUF_DEFAULT_DATAROOM` = 2048).
pub struct Mbuf {
    inner: MbufInner,
}

/// Original or Clone tagged variant of DPDK message buffer.
enum MbufInner {
    /// Original version of the message buffer that should be freed when it goes
    /// out of scope, unless the ownership of the pointer is given back to
    /// DPDK on transmit.
    Original(NonNull<ffi::rte_mbuf>),
    /// A clone version of the message buffer that should not be freed when
    /// it goes out of scope.
    Clone(NonNull<ffi::rte_mbuf>),
}

impl MbufInner {
    fn ptr(&self) -> &NonNull<ffi::rte_mbuf> {
        match self {
            MbufInner::Original(raw) => raw,
            MbufInner::Clone(raw) => raw,
        }
    }

    fn ptr_mut(&mut self) -> &mut NonNull<ffi::rte_mbuf> {
        match self {
            MbufInner::Original(ref mut raw) => raw,
            MbufInner::Clone(ref mut raw) => raw,
        }
    }
}

impl Mbuf {
    /// Creates a new message buffer.
    ///
    /// The Mbuf is allocated from the `Mempool` assigned to the current
    /// executing thread by the `Runtime`. The call will fail if invoked
    /// from a thread not managed by the `Runtime`.
    #[inline]
    pub fn new() -> Fallible<Self> {
        let mempool = MEMPOOL.with(|tls| tls.get());
        let raw =
            unsafe { ffi::_rte_pktmbuf_alloc(mempool).to_result(|_| MempoolError::Exhausted)? };

        Ok(Mbuf {
            inner: MbufInner::Original(raw),
        })
    }

    /// Creates a new message buffer from a byte array.
    #[inline]
    pub fn from_bytes(data: &[u8]) -> Fallible<Self> {
        let mut mbuf = Mbuf::new()?;
        mbuf.extend(0, data.len())?;
        mbuf.write_data_slice(0, data)?;
        Ok(mbuf)
    }

    /// Creates a new `Mbuf` from a raw pointer.
    #[inline]
    pub(crate) unsafe fn from_ptr(ptr: *mut ffi::rte_mbuf) -> Self {
        Mbuf {
            inner: MbufInner::Original(NonNull::new_unchecked(ptr)),
        }
    }

    /// Returns the raw struct needed for FFI calls.
    #[inline]
    fn raw(&self) -> &ffi::rte_mbuf {
        unsafe { self.inner.ptr().as_ref() }
    }

    /// Returns the raw struct needed for FFI calls.
    #[inline]
    fn raw_mut(&mut self) -> &mut ffi::rte_mbuf {
        unsafe { self.inner.ptr_mut().as_mut() }
    }

    /// Returns amount of data stored in the buffer.
    #[inline]
    pub fn data_len(&self) -> usize {
        self.raw().data_len as usize
    }

    /// Returns the raw pointer from the offset
    #[inline]
    pub(crate) unsafe fn data_address(&self, offset: usize) -> *mut u8 {
        let raw = self.raw();
        (raw.buf_addr as *mut u8).offset(raw.data_off as isize + offset as isize)
    }

    /// Returns the amount of bytes left in the buffer.
    #[inline]
    fn tailroom(&self) -> usize {
        let raw = self.raw();
        (raw.buf_len - raw.data_off - raw.data_len) as usize
    }

    /// Extends the data buffer at offset by `len` bytes.
    ///
    /// If the offset is not at the end of the data. The data after the
    /// offset is shifted down to make room.
    #[inline]
    pub fn extend(&mut self, offset: usize, len: usize) -> Fallible<()> {
        ensure!(len > 0, BufferError::NotResized);
        ensure!(offset <= self.data_len(), BufferError::NotResized);
        ensure!(len < self.tailroom(), BufferError::NotResized);

        // shifts down data to make room
        let to_copy = self.data_len() - offset;
        if to_copy > 0 {
            unsafe {
                let src = self.data_address(offset);
                let dst = self.data_address(offset + len);
                ptr::copy(src, dst, to_copy);
            }
        }

        // do some record keeping
        self.raw_mut().data_len += len as u16;
        self.raw_mut().pkt_len += len as u32;

        Ok(())
    }

    /// Shrinks the data buffer at offset by `len` bytes.
    ///
    /// The data at offset is shifted up.
    #[inline]
    pub fn shrink(&mut self, offset: usize, len: usize) -> Fallible<()> {
        ensure!(len > 0, BufferError::NotResized);
        ensure!(offset + len <= self.data_len(), BufferError::NotResized);

        // shifts up data to fill the room
        let to_copy = self.data_len() - offset - len;
        if to_copy > 0 {
            unsafe {
                let src = self.data_address(offset + len);
                let dst = self.data_address(offset);
                ptr::copy(src, dst, to_copy);
            }
        }

        // do some record keeping
        self.raw_mut().data_len -= len as u16;
        self.raw_mut().pkt_len -= len as u32;

        Ok(())
    }

    /// Resizes the data buffer.
    #[inline]
    pub fn resize(&mut self, offset: usize, len: isize) -> Fallible<()> {
        if len < 0 {
            self.shrink(offset, -len as usize)
        } else {
            self.extend(offset, len as usize)
        }
    }

    /// Truncates the data buffer to len.
    #[inline]
    pub fn truncate(&mut self, to_len: usize) -> Fallible<()> {
        ensure!(to_len < self.data_len(), BufferError::NotResized);

        self.raw_mut().data_len = to_len as u16;
        self.raw_mut().pkt_len = to_len as u32;

        Ok(())
    }

    /// Reads the data at offset as `T` and returns it as a raw pointer.
    #[inline]
    pub fn read_data<T: SizeOf>(&self, offset: usize) -> Fallible<NonNull<T>> {
        ensure!(
            offset < self.data_len(),
            BufferError::BadOffset(offset, self.data_len())
        );
        ensure!(
            offset + T::size_of() <= self.data_len(),
            BufferError::OutOfBuffer(T::size_of(), self.data_len() - offset)
        );

        unsafe {
            let item = self.data_address(offset) as *mut T;
            Ok(NonNull::new_unchecked(item))
        }
    }

    /// Writes `T` to the data buffer at offset and returns the new copy
    /// as a raw pointer.
    ///
    /// Before writing to the data buffer, should call `Mbuf::extend` first
    /// to make sure enough space is allocated for the write and data is not
    /// being overridden.
    #[inline]
    pub fn write_data<T: SizeOf>(&mut self, offset: usize, item: &T) -> Fallible<NonNull<T>> {
        ensure!(
            offset + T::size_of() <= self.data_len(),
            BufferError::OutOfBuffer(T::size_of(), self.data_len() - offset)
        );

        unsafe {
            let src = item as *const T;
            let dst = self.data_address(offset) as *mut T;
            ptr::copy_nonoverlapping(src, dst, 1);
        }

        self.read_data(offset)
    }

    /// Reads the data at offset as a slice of `T` and returns the slice as
    /// a raw pointer.
    #[inline]
    pub fn read_data_slice<T: SizeOf>(
        &self,
        offset: usize,
        count: usize,
    ) -> Fallible<NonNull<[T]>> {
        ensure!(
            offset < self.data_len(),
            BufferError::BadOffset(offset, self.data_len())
        );
        ensure!(
            offset + T::size_of() * count <= self.data_len(),
            BufferError::OutOfBuffer(T::size_of() * count, self.data_len() - offset)
        );

        unsafe {
            let item0 = self.data_address(offset) as *mut T;
            let slice = slice::from_raw_parts_mut(item0, count) as *mut [T];
            Ok(NonNull::new_unchecked(slice))
        }
    }

    /// Writes a slice of `T` to the data buffer at offset and returns the
    /// new copy as a raw pointer.
    ///
    /// Before writing to the data buffer, should call `Mbuf::extend` first
    /// to make sure enough space is allocated for the write and data is not
    /// being overridden.
    #[inline]
    pub fn write_data_slice<T: SizeOf>(
        &mut self,
        offset: usize,
        slice: &[T],
    ) -> Fallible<NonNull<[T]>> {
        let count = slice.len();

        ensure!(
            offset + T::size_of() * count <= self.data_len(),
            BufferError::OutOfBuffer(T::size_of() * count, self.data_len() - offset)
        );

        unsafe {
            let src = slice.as_ptr();
            let dst = self.data_address(offset) as *mut T;
            ptr::copy_nonoverlapping(src, dst, count);
        }

        self.read_data_slice(offset, count)
    }

    /// Acquires the underlying raw struct pointer.
    ///
    /// The `Mbuf` is consumed. It is the caller's the responsibility to
    /// free the raw pointer after use. Otherwise the buffer is leaked.
    #[inline]
    pub(crate) fn into_ptr(self) -> *mut ffi::rte_mbuf {
        let ptr = self.inner.ptr().as_ptr();
        mem::forget(self);
        ptr
    }

    /// Allocates a Vec of `Mbuf`s of `len` size.
    pub fn alloc_bulk(len: usize) -> Fallible<Vec<Mbuf>> {
        let mut ptrs = Vec::with_capacity(len);
        let mempool = MEMPOOL.with(|tls| tls.get());

        let mbufs = unsafe {
            ffi::_rte_pktmbuf_alloc_bulk(mempool, ptrs.as_mut_ptr(), len as raw::c_uint)
                .to_result(DpdkError::from_errno)?;

            ptrs.set_len(len);
            ptrs.into_iter()
                .map(|ptr| Mbuf::from_ptr(ptr))
                .collect::<Vec<_>>()
        };

        Ok(mbufs)
    }

    /// Frees the message buffers in bulk.
    pub(crate) fn free_bulk(mbufs: Vec<Mbuf>) {
        let ptrs = mbufs.into_iter().map(Mbuf::into_ptr).collect::<Vec<_>>();
        super::mbuf_free_bulk(ptrs);
    }
}

impl fmt::Debug for Mbuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = self.raw();
        f.debug_struct(&format!("mbuf@{:p}", raw.buf_addr))
            .field("buf_len", &raw.buf_len)
            .field("pkt_len", &raw.pkt_len)
            .field("data_len", &raw.data_len)
            .field("data_off", &raw.data_off)
            .finish()
    }
}

impl Drop for Mbuf {
    fn drop(&mut self) {
        match self.inner {
            MbufInner::Original(_) => {
                trace!("freeing mbuf@{:p}.", self.raw().buf_addr);
                unsafe {
                    ffi::_rte_pktmbuf_free(self.raw_mut());
                }
            }
            MbufInner::Clone(_) => (),
        }
    }
}

// because `Mbuf` holds a raw pointer, by default, rust will deem the struct
// to be not sendable. explicitly implement the `Send` trait to ensure it
// can go across thread boundaries.
unsafe impl Send for Mbuf {}

impl Packet for Mbuf {
    // `Mbuf` does not have a conceptual envelope. However, we need to define
    // it this way to implement the trait.
    type Envelope = Mbuf;

    #[inline]
    fn envelope(&self) -> &Self::Envelope {
        self
    }

    #[inline]
    fn envelope_mut(&mut self) -> &mut Self::Envelope {
        self
    }

    #[inline]
    fn mbuf(&self) -> &Mbuf {
        self
    }

    #[inline]
    fn mbuf_mut(&mut self) -> &mut Mbuf {
        self
    }

    #[inline]
    fn offset(&self) -> usize {
        0
    }

    #[inline]
    fn header_len(&self) -> usize {
        0
    }

    #[inline]
    unsafe fn clone(&self, _internal: Internal) -> Self {
        let raw = self.inner.ptr();
        Mbuf {
            inner: MbufInner::Clone(*raw),
        }
    }

    #[inline]
    fn try_parse(envelope: Self::Envelope, _internal: Internal) -> Fallible<Self> {
        Ok(envelope)
    }

    #[inline]
    fn try_push(envelope: Self::Envelope, _internal: Internal) -> Fallible<Self> {
        Ok(envelope)
    }

    #[inline]
    fn deparse(self) -> Self::Envelope {
        self
    }

    #[inline]
    fn remove(self) -> Fallible<Self::Envelope> {
        Ok(self)
    }

    #[inline]
    fn reset(self) -> Mbuf {
        self
    }

    #[inline]
    fn reconcile_all(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUFFER: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    #[capsule::test]
    fn new_from_bytes() {
        let mbuf = Mbuf::from_bytes(&BUFFER).unwrap();

        let slice = mbuf.read_data_slice::<u8>(0, 16).unwrap();
        let slice = unsafe { slice.as_ref() };
        assert_eq!(BUFFER, slice);
    }

    #[capsule::test]
    fn extend_data_buffer_tail() {
        let mut mbuf = Mbuf::new().unwrap();

        // writes some data to the buffer
        assert!(mbuf.extend(0, 16).is_ok());
        assert_eq!(16, mbuf.data_len());
        assert!(mbuf.write_data_slice(0, &BUFFER).is_ok());

        // extends the tail
        assert!(mbuf.extend(16, 8).is_ok());
        assert_eq!(24, mbuf.data_len());

        // make sure data is untouched
        let slice = mbuf.read_data_slice::<u8>(0, 24).unwrap();
        let slice = unsafe { slice.as_ref() };
        assert_eq!(BUFFER, slice[..16]);
    }

    #[capsule::test]
    fn extend_data_buffer_middle() {
        let mut mbuf = Mbuf::new().unwrap();

        // write some data to the buffer
        assert!(mbuf.extend(0, 16).is_ok());
        assert!(mbuf.write_data_slice(0, &BUFFER).is_ok());

        // extends the middle
        assert!(mbuf.extend(4, 8).is_ok());
        assert_eq!(24, mbuf.data_len());

        // make sure data is untouched
        let slice = mbuf.read_data_slice::<u8>(0, 24).unwrap();
        let slice = unsafe { slice.as_ref() };

        // [0..4] untouched
        assert_eq!(BUFFER[..4], slice[..4]);
        // [4..12] untouched, this is the 'new' memory
        assert_eq!(BUFFER[4..12], slice[4..12]);
        // copied [4..16] to [12..24]
        assert_eq!(BUFFER[4..], slice[12..24]);
    }

    #[capsule::test]
    fn extend_data_buffer_too_much() {
        let mut mbuf = Mbuf::new().unwrap();
        assert!(mbuf.extend(0, 999_999).is_err());
    }

    #[capsule::test]
    fn shrink_data_buffer_tail() {
        let mut mbuf = Mbuf::new().unwrap();

        // write some data to the buffer
        assert!(mbuf.extend(0, 16).is_ok());
        assert!(mbuf.write_data_slice(0, &BUFFER).is_ok());

        // shrinks the tail
        assert!(mbuf.shrink(8, 8).is_ok());
        assert_eq!(8, mbuf.data_len());

        // make sure data is untouched
        let slice = mbuf.read_data_slice::<u8>(0, 8).unwrap();
        let slice = unsafe { slice.as_ref() };
        assert_eq!(BUFFER[..8], slice[..8]);
    }

    #[capsule::test]
    fn shrink_data_buffer_middle() {
        let mut mbuf = Mbuf::new().unwrap();

        // write some data to the buffer
        assert!(mbuf.extend(0, 16).is_ok());
        assert!(mbuf.write_data_slice(0, &BUFFER).is_ok());

        // shrinks the middle
        assert!(mbuf.shrink(4, 8).is_ok());
        assert_eq!(8, mbuf.data_len());

        // make sure data is untouched
        let slice = mbuf.read_data_slice::<u8>(0, 8).unwrap();
        let slice = unsafe { slice.as_ref() };

        // removed [4..12]
        assert_eq!(BUFFER[..4], slice[..4]);
        assert_eq!(BUFFER[12..], slice[4..]);
    }

    #[capsule::test]
    fn shrink_data_buffer_too_much() {
        let mut mbuf = Mbuf::new().unwrap();
        assert!(mbuf.extend(0, 200).is_ok());
        assert!(mbuf.shrink(150, 100).is_err());
    }

    #[capsule::test]
    fn truncate_data_buffer() {
        let mut mbuf = Mbuf::new().unwrap();

        // write some data to the buffer
        assert!(mbuf.extend(0, 16).is_ok());
        assert!(mbuf.write_data_slice(0, &BUFFER).is_ok());

        // truncates the buffer
        assert!(mbuf.truncate(8).is_ok());
        assert_eq!(8, mbuf.data_len());

        // make sure data is untouched
        let slice = mbuf.read_data_slice::<u8>(0, 8).unwrap();
        let slice = unsafe { slice.as_ref() };
        assert_eq!(BUFFER[..8], slice[..8]);
    }

    #[capsule::test]
    fn read_and_write_data() {
        let mut mbuf = Mbuf::new().unwrap();

        // write some data to the buffer
        assert!(mbuf.extend(0, 20).is_ok());
        assert!(mbuf.write_data(0, &BUFFER).is_ok());

        let item = mbuf.read_data::<[u8; 16]>(0).unwrap();
        let item = unsafe { item.as_ref() };
        assert_eq!(BUFFER, *item);

        // read from the wrong offset should return junk
        let item = mbuf.read_data::<[u8; 16]>(2).unwrap();
        let item = unsafe { item.as_ref() };
        assert!(BUFFER != *item);

        // read exceeds buffer should err
        assert!(mbuf.read_data::<[u8; 16]>(10).is_err());
    }

    #[capsule::test]
    fn read_and_write_data_slice() {
        let mut mbuf = Mbuf::new().unwrap();

        // write some data to the buffer
        assert!(mbuf.extend(0, 20).is_ok());
        assert!(mbuf.write_data_slice(0, &BUFFER).is_ok());

        let slice = mbuf.read_data_slice::<u8>(0, 16).unwrap();
        let slice = unsafe { slice.as_ref() };
        assert_eq!(BUFFER, *slice);

        // read from the wrong offset should return junk
        let slice = mbuf.read_data_slice::<u8>(2, 16).unwrap();
        let slice = unsafe { slice.as_ref() };
        assert!(BUFFER != *slice);

        // read exceeds buffer should err
        assert!(mbuf.read_data_slice::<u8>(10, 16).is_err());
    }

    #[capsule::test]
    fn alloc_bulk() {
        let mbufs = Mbuf::alloc_bulk(8).unwrap();
        assert_eq!(8, mbufs.len());

        for mbuf in mbufs {
            assert_eq!(0, mbuf.data_len());
        }
    }
}
