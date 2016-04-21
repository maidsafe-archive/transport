use std::net::UdpSocket;
use std::time::Instant;

use net2;
use nat_traversal;

use endpoint::Endpoint;

pub const RENDEZVOUS_INFO_EXPIRY_DURATION_SECS: u64 = 300;

pub struct PrivTcpInfo {
    pub socket: net2::TcpBuilder,
    pub info: nat_traversal::PrivRendezvousInfo,
}

pub struct PrivUdpInfo {
    pub socket: UdpSocket,
    pub info: nat_traversal::PrivRendezvousInfo,
}

/// The private half of a rendezvous info pair. Used to perform rendezvous connections.
pub struct PrivRendezvousInfo {
    #[doc(hidden)]
    pub priv_tcp_info: Option<PrivTcpInfo>,
    #[doc(hidden)]
    pub priv_udp_info: Option<PrivUdpInfo>,
    #[doc(hidden)]
    pub connection_id_half: u64,
    #[doc(hidden)]
    pub creation_time: Instant,
}

/// The public half of a rendezvous info pair. Share this object with the remote peer and use their
/// `PubRendezvousInfo` to perform a rendezvous connect.
pub struct PubRendezvousInfo {
    #[doc(hidden)]
    pub pub_tcp_info: Option<nat_traversal::PubRendezvousInfo>,
    #[doc(hidden)]
    pub pub_udp_info: Option<nat_traversal::PubRendezvousInfo>,
    #[doc(hidden)]
    pub connection_id_half: u64,
    #[doc(hidden)]
    pub static_endpoints: Vec<Endpoint>,
}

