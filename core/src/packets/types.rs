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

//! Custom primitive wrapper types for converting data to/from network byte
//! order.

use std::convert::From;
use std::fmt;
use std::ops;

/// The 16-bit unsigned integer in big-endian order.
///
/// Used to convert packet fields to host byte order on get and network byte
/// order on set.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C, packed)]
pub struct u16be(pub u16);

impl u16be {
    /// The smallest value that can be represented by this integer type.
    pub const MIN: u16be = u16be(0);
}

impl From<u16> for u16be {
    fn from(item: u16) -> Self {
        u16be(u16::to_be(item))
    }
}

impl From<u16be> for u16 {
    fn from(item: u16be) -> Self {
        u16::from_be(item.0)
    }
}

impl ops::BitAnd for u16be {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        u16be(self.0 & rhs.0)
    }
}

impl ops::BitAndAssign for u16be {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = Self(self.0 & rhs.0)
    }
}

impl ops::BitOr for u16be {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl ops::BitOrAssign for u16be {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = Self(self.0 | rhs.0)
    }
}

impl ops::BitXor for u16be {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl ops::BitXorAssign for u16be {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = Self(self.0 ^ rhs.0)
    }
}

impl ops::Not for u16be {
    type Output = Self;

    fn not(self) -> Self::Output {
        u16be(!self.0)
    }
}

impl fmt::Display for u16be {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let item = self.0;
        item.fmt(f)
    }
}

/// The 32-bit unsigned integer in big-endian order.
///
/// Used to convert packet fields to host byte order on get and network byte
/// order on set.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C, packed)]
pub struct u32be(pub u32);

impl u32be {
    /// The smallest value that can be represented by this integer type.
    pub const MIN: u32be = u32be(0);
}

impl From<u32> for u32be {
    fn from(item: u32) -> Self {
        u32be(u32::to_be(item))
    }
}

impl From<u32be> for u32 {
    fn from(item: u32be) -> Self {
        u32::from_be(item.0)
    }
}

impl ops::BitAnd for u32be {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        u32be(self.0 & rhs.0)
    }
}

impl ops::BitAndAssign for u32be {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = Self(self.0 & rhs.0)
    }
}

impl ops::BitOr for u32be {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl ops::BitOrAssign for u32be {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = Self(self.0 | rhs.0)
    }
}

impl ops::BitXor for u32be {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl ops::BitXorAssign for u32be {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = Self(self.0 ^ rhs.0)
    }
}

impl ops::Not for u32be {
    type Output = Self;

    fn not(self) -> Self::Output {
        u32be(!self.0)
    }
}

impl fmt::Display for u32be {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let item = self.0;
        item.fmt(f)
    }
}
