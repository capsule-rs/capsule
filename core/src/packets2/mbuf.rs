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

use crate::ffi::dpdk;
use crate::packets2::{Packet, SizeOf};
use crate::runtime::Mempool;
use crate::{ensure, trace};
use anyhow::Result;
use capsule_ffi as cffi;
use std::fmt;
use std::mem;
use std::ptr::{self, NonNull};
use std::slice;
use thiserror::Error;

/// Error indicating buffer access failures.
#[derive(Debug, Error)]
pub enum BufferError {
    /// Cannot push, parse or remove Mbuf as a packet.
    #[error("Cannot push, parse or remove Mbuf as a packet.")]
    NotSupported,

    /// The offset exceeds the data length.
    #[error("Offset {0} exceeds the data length {1}.")]
    InvalidOffset(usize, usize),

    /// Cannot extend or shrink the data length by 0 bytes.
    #[error("Cannot extend or shrink the data length by 0 bytes.")]
    InvalidLength,

    /// The struct size exceeds the remaining data length.
    #[error("Struct size {0} exceeds the remaining data length {1}.")]
    OutOfBuffer(usize, usize),

    /// The extend will exceed the maximum buffer capacity.
    #[error("Cannot extend by {0} bytes. Only {1} bytes left of max buffer capacity.")]
    OverMaxBuffer(usize, usize),
}

/// A DPDK message buffer that carries the network packet.
///
/// The buffer has a maximum capacity of `RTE_MBUF_DEFAULT_DATAROOM`. The
/// default value is `2048` bytes, but can be adjusted when compiling DPDK.
/// `data_len` marks the portion of the buffer containing actual data. Before
/// writing new bytes to the buffer, call `extend` to adjust the data portion
/// of the buffer to make room, or existing data will be overridden.
///
/// # Remarks
///
/// Multi-segment Mbuf is not supported. It's the application's responsibilty
/// to ensure that the ethernet device's MTU is less than the default size
/// of a single Mbuf segment.
pub struct Mbuf(NonNull<cffi::rte_mbuf>);

impl Mbuf {
    /// Allocates a new message buffer.
    ///
    /// The Mbuf is allocated from the `Mempool` assigned to the current
    /// executing thread by the `Runtime`. The call will fail if invoked
    /// from a thread not managed by the `Runtime`.
    ///
    /// # Errors
    ///
    /// Returns `MempoolPtrUnsetError` if invoked from a non lcore.
    /// Returns `DpdkError` if the allocation of mbuf fails.
    #[inline]
    pub fn new() -> Result<Self> {
        let mut mp = Mempool::thread_local_ptr()?;
        let ptr = dpdk::pktmbuf_alloc(&mut mp)?;
        Ok(Mbuf(ptr.into()))
    }

    /// Allocates a new message buffer and writes the data to it.
    ///
    /// # Errors
    ///
    /// Returns `DpdkError` if the allocation of mbuf fails.
    /// Returns `BufferError::OverMaxBuffer` if the data is larger than the
    /// maximum buffer capacity.
    #[inline]
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut mbuf = Mbuf::new()?;
        mbuf.extend(0, data.len())?;
        mbuf.write_data_slice(0, data)?;
        Ok(mbuf)
    }

    /// Returns the raw struct needed for FFI calls.
    #[inline]
    fn raw(&self) -> &cffi::rte_mbuf {
        unsafe { self.0.as_ref() }
    }

    /// Returns the raw struct needed for FFI calls.
    #[inline]
    fn raw_mut(&mut self) -> &mut cffi::rte_mbuf {
        unsafe { self.0.as_mut() }
    }

    /// Returns the length of data written in the buffer.
    #[inline]
    pub fn data_len(&self) -> usize {
        self.raw().data_len as usize
    }

    /// Returns the raw pointer from the offset
    #[inline]
    unsafe fn data_address(&self, offset: usize) -> *mut u8 {
        let raw = self.raw();
        (raw.buf_addr as *mut u8).offset(raw.data_off as isize + offset as isize)
    }

    /// Returns the amount of unused bytes left in the buffer.
    #[inline]
    fn tailroom(&self) -> usize {
        let raw = self.raw();
        (raw.buf_len - raw.data_off - raw.data_len) as usize
    }

    /// Extends the data at offset by `len` bytes.
    ///
    /// If the offset is not at the end of the data. The data after the
    /// offset is shifted down to make room.
    ///
    /// # Errors
    ///
    /// Returns `BufferError::InvalidOffset` if the offset is out of bound.
    /// Returns `BufferError::InvalidLength` if the length to extend is 0.
    /// Returns `BufferError::OverMaxBuffer` if the length exceeds the used
    /// buffer capacity.
    #[inline]
    pub fn extend(&mut self, offset: usize, len: usize) -> Result<()> {
        ensure!(len > 0, BufferError::InvalidLength);
        ensure!(
            offset <= self.data_len(),
            BufferError::InvalidOffset(offset, self.data_len())
        );
        ensure!(
            len < self.tailroom(),
            BufferError::OverMaxBuffer(len, self.tailroom())
        );

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

    /// Shrinks the data at offset by `len` bytes.
    ///
    /// The data at offset is shifted up.
    ///
    /// # Errors
    ///
    /// Returns `BufferError::InvalidLength` if the length to shrink is 0.
    /// Returns `BufferError::OutOfBuffer` if the length exceeds the remaining
    /// data length starting at offset.
    #[inline]
    pub fn shrink(&mut self, offset: usize, len: usize) -> Result<()> {
        ensure!(len > 0, BufferError::InvalidLength);
        ensure!(
            offset + len <= self.data_len(),
            BufferError::OutOfBuffer(len, self.data_len() - offset)
        );

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

    /// Resizes the data length.
    ///
    /// Delegates to either `extend` or `shrink`.
    #[inline]
    pub fn resize(&mut self, offset: usize, len: isize) -> Result<()> {
        if len < 0 {
            self.shrink(offset, -len as usize)
        } else {
            self.extend(offset, len as usize)
        }
    }

    /// Truncates the data length to len.
    ///
    /// # Errors
    ///
    /// Returns `BufferError::OutOfBuffer` if the target length exceeds the
    /// data length.
    #[inline]
    pub fn truncate(&mut self, to_len: usize) -> Result<()> {
        ensure!(
            to_len < self.data_len(),
            BufferError::OutOfBuffer(to_len, self.data_len())
        );

        self.raw_mut().data_len = to_len as u16;
        self.raw_mut().pkt_len = to_len as u32;

        Ok(())
    }

    /// Reads the data at offset as `T` and returns it as a raw pointer.
    ///
    /// # Errors
    ///
    /// Returns `BufferError::InvalidOffset` if the offset is out of bound.
    /// Returns `BufferError::OutOfBuffer` if the size of `T` exceeds the
    /// size of the data stored at offset.
    #[inline]
    pub fn read_data<T: SizeOf>(&self, offset: usize) -> Result<NonNull<T>> {
        ensure!(
            offset < self.data_len(),
            BufferError::InvalidOffset(offset, self.data_len())
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

    /// Writes `T` to the buffer at offset and returns it as a raw pointer.
    ///
    /// Before writing to the buffer, should call `Mbuf::extend` first to make
    /// sure enough space is allocated for the write and data is not being
    /// overridden.
    ///
    /// # Errors
    ///
    /// Returns `BufferError::OutOfBuffer` if the size of `T` exceeds the
    /// available data length starting at offset.
    #[inline]
    pub fn write_data<T: SizeOf>(&mut self, offset: usize, item: &T) -> Result<NonNull<T>> {
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
    ///
    /// # Errors
    ///
    /// Returns `BufferError::InvalidOffset` if the offset is out of bound.
    /// Returns `BufferError::OutOfBuffer` if the size of `T` slice exceeds
    /// the size of the data stored at offset.
    #[inline]
    pub fn read_data_slice<T: SizeOf>(&self, offset: usize, count: usize) -> Result<NonNull<[T]>> {
        ensure!(
            offset < self.data_len(),
            BufferError::InvalidOffset(offset, self.data_len())
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

    /// Writes a slice of `T` to the buffer at offset and returns the slice
    /// as a raw pointer.
    ///
    /// Before writing to the buffer, should call `Mbuf::extend` first to make
    /// sure enough space is allocated for the write and data is not being
    /// overridden.
    ///
    /// # Errors
    ///
    /// Returns `BufferError::OutOfBuffer` if the size of `T` slice exceeds
    /// the available data length starting at offset.
    #[inline]
    pub fn write_data_slice<T: SizeOf>(
        &mut self,
        offset: usize,
        slice: &[T],
    ) -> Result<NonNull<[T]>> {
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

    /// Allocates a Vec of `Mbuf`s of `len` size.
    ///
    /// # Errors
    ///
    /// Returns `DpdkError` if the allocation of mbuf fails.
    pub fn alloc_bulk(len: usize) -> Result<Vec<Mbuf>> {
        let mut ptrs = Vec::with_capacity(len);
        let mut mp = Mempool::thread_local_ptr()?;
        dpdk::pktmbuf_alloc_bulk(&mut mp, &mut ptrs)?;

        unsafe {
            // can safely reinterpret Vec<MbufPtr> as Vec<Mbuf>.
            Ok(mem::transmute(ptrs))
        }
    }

    /// Frees the message buffers in bulk.
    pub fn free_bulk(mbufs: Vec<Mbuf>) {
        let mut ptrs = unsafe {
            // can safely reinterpret Vec<Mbuf> as Vec<MbufPtr>.
            mem::transmute(mbufs)
        };
        dpdk::pktmbuf_free_bulk(&mut ptrs);
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
        trace!("freeing mbuf@{:p}.", self.raw().buf_addr);
        // todo: extra clone, hmmm...
        dpdk::pktmbuf_free(self.0.clone().into());
    }
}

// because `Mbuf` holds a raw pointer, by default, rust will deem the struct
// to be not sendable. explicitly implement the `Send` trait to ensure it
// can go across thread boundaries.
unsafe impl Send for Mbuf {}

impl<'env> Packet<'env> for Mbuf {
    // `Mbuf` does not have a conceptual envelope. However, we need to define
    // it this way to implement the trait.
    type Envelope = Mbuf;

    #[inline]
    fn envelope<'local>(&'local self) -> &'local Self::Envelope
    where
        'env: 'local,
    {
        self
    }

    #[inline]
    fn envelope_mut<'local>(&'local mut self) -> &'local mut Self::Envelope
    where
        'env: 'local,
    {
        self
    }

    #[inline]
    fn mbuf<'local>(&'local self) -> &'local Mbuf
    where
        'env: 'local,
    {
        self
    }

    #[inline]
    fn mbuf_mut<'local>(&'local mut self) -> &'local mut Mbuf
    where
        'env: 'local,
    {
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
    fn try_parse(_envelope: &'env mut Self::Envelope) -> Result<Self> {
        Err(BufferError::NotSupported.into())
    }

    #[inline]
    fn try_push(_envelope: &'env mut Self::Envelope) -> Result<Self> {
        Err(BufferError::NotSupported.into())
    }

    #[inline]
    fn remove(self) -> Result<()> {
        Err(BufferError::NotSupported.into())
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

    #[capsule::test(mempool_capacity = 4)]
    fn free_bulk() {
        let mbufs = Mbuf::alloc_bulk(4).unwrap();

        // pool exhausted, should fail
        assert!(Mbuf::new().is_err());

        Mbuf::free_bulk(mbufs);

        // pool replenished after free, should not fail
        assert!(Mbuf::new().is_ok());
    }
}
