#![no_std]

pub const MAX_DNS_NAME_LENGTH: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsQuery {
    pub record_type: u16,
    pub class: u16,
    pub name: [u8; MAX_DNS_NAME_LENGTH],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsQuery {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsRecordA {
    pub ip: u32,
    pub ttl: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsRecordA {}
