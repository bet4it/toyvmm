// Copyright 2023 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub use utils::errno;

pub fn get_page_size() -> Result<usize, errno::Error> {
    match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
        -1 => Err(errno::Error::last()),
        ps => Ok(ps as usize),
    }
}

/// Safely converts a u64 value to a usize value.
/// This bypasses the Clippy lint check because we only support 64-bit platforms.
#[cfg(target_pointer_width = "64")]
#[inline]
#[allow(clippy::cast_possible_truncation)]
pub const fn u64_to_usize(num: u64) -> usize {
    num as usize
}

/// Safely converts a usize value to a u64 value.
/// This bypasses the Clippy lint check because we only support 64-bit platforms.
#[cfg(target_pointer_width = "64")]
#[inline]
#[allow(clippy::cast_possible_truncation)]
pub const fn usize_to_u64(num: usize) -> u64 {
    num as u64
}

#[cfg(test)]
pub mod tests {
    use super::get_page_size;
    #[test]
    fn test_get_page_size() {
        let page_size = get_page_size().expect("Cannot retrieve page size");
        assert_eq!(4096, page_size);
    }
}
