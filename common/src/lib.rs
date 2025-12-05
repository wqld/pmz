#![no_std]

pub const MAX_DNS_NAME_LENGTH: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Config {
    pub host_netns: u64,
    pub service_addr: u32,
    pub subnet_mask: u32,
    pub proxy_pid: u32,
    pub dummy: u16,
    pub proxy_port: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Config {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct SockKey {
    pub src_ip: u32,
    pub src_port: u32,
    pub dst_ip: u32,
    pub dst_port: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SockKey {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DnsHdr {
    pub id: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SockPair {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SockPair {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SockAddr {
    pub addr: u32,
    pub dummy: u16,
    pub port: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SockAddr {}
