use core::{mem, str};

use aya_ebpf::{bindings::TC_ACT_PIPE, programs::TcContext};
use aya_log_ebpf::{error, info};
use common::{DnsQuery, MAX_DNS_NAME_LENGTH};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};

use crate::SERVICE_REGISTRY;

pub const RAW_QUERY: u16 = 1 << 15;
const RAW_OPCODE_SHIFT: u16 = 11;
const RAW_OPCODE_MASK: u16 = 0b1111;
// const RAW_AA: u16 = 1 << 10;
// const RAW_TC: u16 = 1 << 9;
// const RAW_RD: u16 = 1 << 8;
// const RAW_RA: u16 = 1 << 7;
const RAW_RCODE_SHIFT: u16 = 0;
const RAW_RCODE_MASK: u16 = 0b1111;

const DNS_PAYLOAD_OFFSET: usize = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + DnsHdr::LEN;
const RECORD_TYPE_OFFSET: usize = 1;
const CLASS_OFFSET: usize = 3;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DnsHdr {
    pub id: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

impl DnsHdr {
    pub const LEN: usize = mem::size_of::<DnsHdr>();

    pub fn load(ctx: &TcContext) -> Result<Self, &'static str> {
        let mut dns_hdr: DnsHdr = ctx
            .load(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)
            .map_err(|_| "failed to load dns header")?;

        dns_hdr.to_host_endian();
        Ok(dns_hdr)
    }

    pub fn is_standard_query(&self) -> bool {
        self.query() == 0 && self.opcode() == 0
    }

    pub fn rcode_to_str(&self) -> &'static str {
        match self.rcode() {
            0 => "OK",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            _ => "UNKNOWN",
        }
    }

    fn query(&self) -> u16 {
        self.flags & RAW_QUERY
    }

    fn opcode(&self) -> u16 {
        (self.flags >> RAW_OPCODE_SHIFT) & RAW_OPCODE_MASK
    }

    fn rcode(&self) -> u16 {
        (self.flags >> RAW_RCODE_SHIFT) & RAW_RCODE_MASK
    }

    fn to_host_endian(&mut self) {
        self.id = u16::from_be(self.id);
        self.flags = u16::from_be(self.flags);
        self.question_count = u16::from_be(self.question_count);
        self.answer_count = u16::from_be(self.answer_count);
        self.authority_count = u16::from_be(self.authority_count);
        self.additional_count = u16::from_be(self.additional_count);
    }
}

pub struct DnsResolver {}

impl DnsResolver {
    pub fn handle_query(ctx: &TcContext) -> Result<i32, &'static str> {
        let mut dns_query = DnsQuery {
            record_type: 0,
            class: 0,
            name: unsafe { mem::zeroed() },
        };

        Self::parse_query(ctx, &mut dns_query)?;

        info!(
            ctx,
            "DNS_NAME={} DNS_TYPE={} DNS_CLASS={}",
            unsafe { str::from_utf8_unchecked(&dns_query.name) },
            Self::record_type_to_str(dns_query.record_type),
            Self::class_to_str(dns_query.class),
        );

        match unsafe { SERVICE_REGISTRY.get(&dns_query) } {
            Some(_a_record) => {
                info!(ctx, "some");
                Ok(TC_ACT_PIPE)
            }
            None => {
                info!(ctx, "none");
                Ok(TC_ACT_PIPE)
            }
        }
    }

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

    fn parse_query(ctx: &TcContext, dns_query: &mut DnsQuery) -> Result<(), &'static str> {
        let buf_len = ctx.len() as usize;

        let mut cur_buf_idx = DNS_PAYLOAD_OFFSET;
        let mut name_idx = 0;
        let mut cur_label_len = None;
        let mut cur_label_idx = 0;

        while name_idx < MAX_DNS_NAME_LENGTH {
            if cur_buf_idx + 1 > buf_len {
                error!(ctx, "boundary exceeded while parsing DNS query name");
                break;
            }

            let c: u8 = ctx
                .load(cur_buf_idx)
                .map_err(|_| "failed to read DNS query name byte")?;

            if c == 0 {
                break;
            }

            if let Some(label_len) = cur_label_len {
                if cur_label_idx == label_len as usize {
                    dns_query.name[name_idx] = b'.';
                    cur_label_len = None;
                    cur_label_idx = 0;
                    name_idx += 1;
                    continue;
                }

                dns_query.name[name_idx] = c;
                cur_label_idx += 1;
                name_idx += 1;
            } else {
                cur_label_len = Some(c);
            }

            cur_buf_idx += 1;
        }

        if (cur_buf_idx + 5) > buf_len {
            error!(
                ctx,
                "boundary exceeded while retrieving DNS record type and class"
            );
        } else {
            let record_type: u16 = ctx
                .load(cur_buf_idx + RECORD_TYPE_OFFSET)
                .map_err(|_| "failed to read record type")?;
            let class: u16 = ctx
                .load(cur_buf_idx + CLASS_OFFSET)
                .map_err(|_| "failed to read class")?;

            dns_query.record_type = u16::from_be(record_type);
            dns_query.class = u16::from_be(class);
        }

        Ok(())
    }
}
