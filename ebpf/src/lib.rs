#![no_std]

use core::mem;

#[inline(always)]
pub fn prt_at<T>(start: usize, end: usize, offset: usize) -> Result<*const T, ()> {
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
pub fn ptr_at_mut<T>(start: usize, end: usize, offset: usize) -> Result<*mut T, ()> {
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

// This file exists to enable the library target.
pub fn record_type_to_str(record_type: u16) -> &'static str {
    match record_type {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        _ => "UNKNOWN",
    }
}

/// Convert class to string
pub fn class_to_str(class: u16) -> &'static str {
    match class {
        1 => "IN",
        2 => "CS",
        3 => "CH",
        4 => "HS",
        _ => "UNKNOWN",
    }
}
