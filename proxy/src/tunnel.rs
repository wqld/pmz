pub mod client;
pub mod server;
pub mod stream;
pub mod verifier;

pub const PMZ_PROTO_HDR: &str = "Pmz-Proto";
pub const PROTO_TCP: &str = "TCP";
pub const PROTO_UDP: &str = "UDP";

enum PROTO {
    TCP,
    UDP,
}

impl PROTO {
    pub fn from(s: &str) -> Self {
        if s.eq(PROTO_UDP) {
            return PROTO::UDP;
        }

        PROTO::TCP
    }
}
