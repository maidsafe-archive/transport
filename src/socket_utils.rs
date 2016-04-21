use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub fn ipv4_addr_is_unspecified(ip: &Ipv4Addr) -> bool {
    ip.octets() == [0, 0, 0, 0]
}

pub fn ipv4_addr_unspecified_to_loopback(ip: Ipv4Addr) -> Ipv4Addr {
    //if ip.is_unspecified() { // TODO(canndrew): Use this when it's stable
    if ipv4_addr_is_unspecified(&ip) {
        Ipv4Addr::new(127, 0, 0, 1)
    }
    else {
        ip
    }
}

pub fn ipv6_addr_unspecified_to_loopback(ip: Ipv6Addr) -> Ipv6Addr {
    if ip.is_unspecified() {
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)
    }
    else {
        ip
    }
}

pub fn ip_addr_unspecified_to_loopback(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ipv4_addr) => IpAddr::V4(ipv4_addr_unspecified_to_loopback(ipv4_addr)),
        IpAddr::V6(ipv6_addr) => IpAddr::V6(ipv6_addr_unspecified_to_loopback(ipv6_addr)),
    }
}

pub fn socket_addr_unspecified_to_loopback(addr: SocketAddr) -> SocketAddr {
    let ip = ip_addr_unspecified_to_loopback(addr.ip());
    let port = addr.port();
    SocketAddr::new(ip, port)
}

