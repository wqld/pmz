use core::{
    mem,
    ops::{Deref, DerefMut},
    str,
};

use aya_ebpf::{
    bindings::{__sk_buff, BPF_F_INGRESS, TC_ACT_PIPE, TC_ACT_REDIRECT},
    helpers::{bpf_redirect, bpf_skb_change_tail},
    programs::TcContext,
    EbpfContext,
};
use aya_log_ebpf::{debug, error};
use common::{DnsHdr, DnsQuery, DnsRecordA, MAX_DNS_NAME_LENGTH};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, udp::UdpHdr};
// use pmz_ebpf::{class_to_str, record_type_to_str};

use crate::{context::Context, SERVICE_REGISTRY};

pub const MAX_DNS_BUFFER_LENGTH: usize = DnsAnswer::LEN + 4;

pub const RAW_QUERY: u16 = 1 << 15;
const RAW_OPCODE_SHIFT: u16 = 11;
const RAW_OPCODE_MASK: u16 = 0b1111;

const DNS_LEN: usize = mem::size_of::<DnsHdr>();
const DNS_PAYLOAD_OFFSET: usize = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + DNS_LEN;
const RECORD_TYPE_OFFSET: usize = 1;
const CLASS_OFFSET: usize = 3;

enum DnsNameStage {
    INIT,
    LABEL,
    NAME(u8),
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct DnsAnswer {
    query_pointer: u16,
    record_type: u16,
    class: u16,
    ttl: u32,
    data_length: u16,
}

impl DnsAnswer {
    pub const LEN: usize = mem::size_of::<DnsAnswer>();

    pub fn from_a_record(a_record: &DnsRecordA) -> Self {
        Self {
            query_pointer: 0xc00c_u16.to_be(),
            record_type: 0x0001_u16.to_be(),
            class: 0x0001_u16.to_be(),
            ttl: a_record.ttl.to_be(),
            data_length: 4_u16.to_be(),
        }
    }

    #[inline(always)]
    pub fn write_to_buffer(&self, dns_buf: &mut [u8], ip: u32) {
        let resp_slice = &mut dns_buf[..Self::LEN];
        let resp_ptr = resp_slice.as_mut_ptr() as *mut DnsAnswer;

        unsafe {
            *resp_ptr = *self;
        }

        let ip_bytes = ip.to_be_bytes();
        let ip_slice = &mut dns_buf[Self::LEN..Self::LEN + 4];
        ip_slice.copy_from_slice(&ip_bytes);
    }
}

pub struct DnsResolver<'a> {
    ctx: &'a mut Context<'a, TcContext>,
}

impl<'a> Deref for DnsResolver<'a> {
    type Target = Context<'a, TcContext>;

    fn deref(&self) -> &Self::Target {
        self.ctx
    }
}

impl<'a> DerefMut for DnsResolver<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ctx
    }
}

impl<'a> DnsResolver<'a> {
    pub fn new(ctx: &'a mut Context<'a, TcContext>) -> Self {
        Self { ctx }
    }

    pub fn handle(&mut self) -> Result<i32, &'static str> {
        if !self.is_standard_query() {
            return Ok(TC_ACT_PIPE);
        }

        let mut dns_query = DnsQuery {
            record_type: 0,
            class: 0,
            name: unsafe { mem::zeroed() },
        };

        let query_len = self.parse_query(&mut dns_query)?;

        // TODO: need to check
        // The BPF verifier rejects the following debug! macro on kernel versions 5.15 and below.
        // debug!(
        //     self.ctx.ctx,
        //     "DNS_NAME={} DNS_TYPE={} DNS_CLASS={}",
        //     unsafe { str::from_utf8_unchecked(&dns_query.name) },
        //     record_type_to_str(dns_query.record_type),
        //     class_to_str(dns_query.class),
        // );

        match unsafe { SERVICE_REGISTRY.get(&dns_query) } {
            Some(a_record) => {
                debug!(self.ctx.ctx, "some");

                let mut extra_dns_buf = [0u8; MAX_DNS_BUFFER_LENGTH];

                let dns_answer = DnsAnswer::from_a_record(a_record);
                dns_answer.write_to_buffer(&mut extra_dns_buf, a_record.ip);

                let answer_start = DNS_PAYLOAD_OFFSET + query_len;
                let tail_adjust = answer_start + MAX_DNS_BUFFER_LENGTH - self.len() as usize;
                let new_skb_len = self.len() + tail_adjust as u32;

                unsafe {
                    let skb = self.as_ptr() as *mut __sk_buff;
                    match bpf_skb_change_tail(skb, new_skb_len, 0) {
                        n if n < 0 => {
                            error!(self.ctx.ctx, "failed to change tail: {}", n);
                            return Ok(TC_ACT_PIPE);
                        }
                        _ => {}
                    }
                }

                self.store(answer_start, &extra_dns_buf, 0)
                    .map_err(|_| "failed to store dns_response")?;

                self.update_hdrs_for_dns()
                    .map_err(|_| "failed to update headers for dns")?;

                unsafe {
                    self.swap_src_dst();
                    self.ignore_udp_csum();
                    self.set_dns_response_flags();
                    self.recompute_ip_csum();

                    let raw_skb = &*(self.as_ptr() as *mut __sk_buff);
                    bpf_redirect(raw_skb.ifindex, BPF_F_INGRESS as u64);
                }

                Ok(TC_ACT_REDIRECT)
            }
            None => {
                debug!(self.ctx.ctx, "none");
                Ok(TC_ACT_PIPE)
            }
        }
    }

    fn is_standard_query(&self) -> bool {
        let flags = u16::from_be((unsafe { *self.dns_hdr }).flags);
        let query = flags & RAW_QUERY;
        let opcode = (flags >> RAW_OPCODE_SHIFT) & RAW_OPCODE_MASK;

        query == 0 && opcode == 0
    }

    unsafe fn set_dns_response_flags(&mut self) {
        (*self.dns_hdr).flags |= 0x8080;
        (*self.dns_hdr).answer_count = 1u16.to_be();
        (*self.dns_hdr).additional_count = 0u16.to_be();
    }

    #[inline(always)]
    fn parse_query(&self, dns_query: &mut DnsQuery) -> Result<usize, &'static str> {
        let data_end = self.data_end() as usize;
        let mut dns_name_sate = DnsNameStage::INIT;
        let mut data_idx = DNS_PAYLOAD_OFFSET;
        let mut name_idx = 0;

        while name_idx < MAX_DNS_NAME_LENGTH {
            if data_idx + 1 > data_end {
                error!(
                    self.ctx.ctx,
                    "boundary exceeded while parsing DNS query name"
                );
                break;
            }

            let c: u8 = self
                .load(data_idx)
                .map_err(|_| "failed to read DNS query name byte")?;

            if c == 0 {
                break;
            }

            dns_name_sate = match dns_name_sate {
                DnsNameStage::INIT => DnsNameStage::NAME(c),
                DnsNameStage::LABEL => {
                    dns_query.name[name_idx] = b'.';
                    name_idx += 1;
                    DnsNameStage::NAME(c)
                }
                DnsNameStage::NAME(len) => {
                    dns_query.name[name_idx] = c;
                    name_idx += 1;
                    if len - 1 == 0 {
                        DnsNameStage::LABEL
                    } else {
                        DnsNameStage::NAME(len - 1)
                    }
                }
            };

            data_idx += 1;
        }

        if (data_idx + 5) > data_end {
            error!(
                self.ctx.ctx,
                "boundary exceeded while retrieving DNS record type and class"
            );
        } else {
            let record_type: u16 = self
                .load(data_idx + RECORD_TYPE_OFFSET)
                .map_err(|_| "failed to read record type")?;
            let class: u16 = self
                .load(data_idx + CLASS_OFFSET)
                .map_err(|_| "failed to read class")?;

            dns_query.record_type = u16::from_be(record_type);
            dns_query.class = u16::from_be(class);
        }

        Ok(data_idx + 1 + 2 + 2 - DNS_PAYLOAD_OFFSET)
    }
}
