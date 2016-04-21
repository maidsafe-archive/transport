//! Defines the `ListenEndpoint` type and related items.

use std::error;
use std::iter;
use std::fmt;
use std::io;
use std::str::FromStr;
use std::net;
use std::net::{ToSocketAddrs, IpAddr};

use url;
use void::Void;
use socket_addr::SocketAddr;

use protocol::Protocol;
use protocol;

/// Enum representing listening endpoint of supported protocols
#[derive(Copy, Debug, Eq, PartialEq, Hash, Clone, RustcEncodable, RustcDecodable)]
pub enum ListenEndpoint {
    /// A TCP listen endpoint.
    Tcp(SocketAddr),
    /// A uTP listen endpoint.
    Utp(SocketAddr),
}

impl ListenEndpoint {
    /// Get the protocol of this endpoint.
    pub fn protocol(&self) -> Protocol {
        match *self {
            ListenEndpoint::Utp(..) => Protocol::Utp,
            ListenEndpoint::Tcp(..) => Protocol::Tcp,
        }
    }

    /*
    pub fn is_loopback(&self) -> bool {
        match self.socket_addr.ip() {
            IpAddr::V4(ipv4_addr) => ipv4_addr.is_loopback(),
            IpAddr::V6(ipv6_addr) => ipv6_addr.is_loopback(),
        }
    }
    */
}

impl fmt::Display for ListenEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ListenEndpoint::Tcp(addr) => write!(f, "tcp-listen://{}/", addr),
            ListenEndpoint::Utp(addr) => write!(f, "utp-listen://{}/", addr),
        }
    }
}

/// A trait for types that can be converted to an iterator of listen endpoints. This is similar to
/// the `ToSocketAddrs` trait from the standard library.
pub trait ToListenEndpoints {
    /// Errors that can occur when parsing the next endpoint.
    type Err: error::Error + Send + 'static;

    /// The iterator returned by `to_listen_endpoints`.
    type Iter: Iterator<Item=Result<ListenEndpoint, Self::Err>>;

    /// Returns an iterator that yields a sequence of listen endpoints (or errors).
    fn to_listen_endpoints(&self) -> Self::Iter;
}

impl ToListenEndpoints for ListenEndpoint {
    type Err = Void;
    type Iter = iter::Once<Result<ListenEndpoint, Void>>;

    fn to_listen_endpoints(&self) -> iter::Once<Result<ListenEndpoint, Void>> {
        iter::once(Ok(*self))
    }
}

impl ToListenEndpoints for str {
    type Err = ParseListenEndpointError;
    type Iter = iter::Once<Result<ListenEndpoint, ParseListenEndpointError>>;

    fn to_listen_endpoints(&self) -> iter::Once<Result<ListenEndpoint, ParseListenEndpointError>> {
        iter::once(ListenEndpoint::from_str(self))
    }
}

impl<'a, T: ToListenEndpoints + ?Sized> ToListenEndpoints for &'a T {
    type Err = T::Err;
    type Iter = T::Iter;

    fn to_listen_endpoints(&self) -> T::Iter {
        (*self).to_listen_endpoints()
    }
}

/// Iterator returned when `ToListenEndpoints::to_listen_endpoints` is called on a slice.
pub struct SliceListenEndpointsIter<'a, E: ToListenEndpoints + 'a> {
    slice: &'a [E],
    iter: Option<E::Iter>,
}

impl<'a, E: ToListenEndpoints + 'a> ToListenEndpoints for &'a [E] {
    type Iter = SliceListenEndpointsIter<'a, E>;
    type Err = E::Err;

    fn to_listen_endpoints(&self) -> SliceListenEndpointsIter<'a, E> {
        match self.len() {
            0 => SliceListenEndpointsIter {
                slice: &[],
                iter: None,
            },
            _ => SliceListenEndpointsIter {
                slice: &self[1..],
                iter: Some(self[0].to_listen_endpoints()),
            },
        }
    }
}

impl<'a, E: ToListenEndpoints + 'a> Iterator for SliceListenEndpointsIter<'a, E> {
    type Item = Result<ListenEndpoint, E::Err>;

    fn next(&mut self) -> Option<Result<ListenEndpoint, E::Err>> {
        loop {
            match self.iter {
                None => return None,
                Some(ref mut iter) => {
                    let res = iter.next();
                    match res {
                        Some(x) => return Some(x),
                        None => (),
                    };
                },
            };
            match self.slice.len() {
                0 => self.iter = None,
                _ => {
                    self.iter = Some(self.slice[0].to_listen_endpoints());
                    self.slice = &self.slice[1..];
                },
            }
        }
    }
}

quick_error! {
    /// Errors returned by `FromStr::from_str` when parsing an `ListenEndpoint`
    #[derive(Debug)]
    pub enum ParseListenEndpointError {
        /// Error parsing url
        BadUrl(err: url::ParseError) {
            description("Error parsing url")
            display("Error parsing url: {}", err)
            cause(err)
        }
        /// Listen endpoint url contains unexpected query
        UnexpectedQuery(query: String) {
            description("Listen endpoint url contains unexpected query")
            display("Listen endpoint url contains unexpected query: {:?}", query)
        }
        /// Listen endpoint url contains unexpected fragment")
        UnexpectedFragment(fragment: String) {
            description("Listen endpoint url contains unexpected fragment")
            display("Listen endpoint url contains unexpected fragment: {:?}", fragment)
        }
        /// Listen endpoint url contains unexpected username
        UnexpectedUsername(username: String) {
            description("Listen endpoint url contains unexpected username")
            display("Listen endpoint url contains unexpected username: {:?}", username)
        }
        /// Listen endpoint url contains unexpected password
        UnexpectedPassword {
            description("Listen endpoint url contains unexpected password")
        }
        /// Listen endpoint url contains unexpected path
        UnexpectedPath(path: Vec<String>) {
            description("Listen endpoint url contains unexpected path")
            display("Listen endpoint url contains unexpected path: {:?}", path)
        }
        /// Failed to parse the address of the listen endpoint url
        ParseAddr(err: io::Error) {
            description("Failed to parse the address of the listen endpoint url")
            display("Failed to parse the address of the listen endpoint url: {}", err)
            cause(err)
        }
        /// Listen endpoint url is missing the address
        MissingAddr {
            description("Listen endpoint url is missing the address")
        }
        /// Multiple addresses were parsed from the listen endpoint url
        MultipleAddrs(a0: SocketAddr, a1: SocketAddr) {
            description("Multiple addresses were parsed from the listen endpoint url")
            display("Multiple addresses were parsed from the listen endpoint url: {} and {}", a0, a1)
        }
        /// Unknown scheme in listen endpoint url
        UnknownScheme(scheme: String) {
            description("Unknown scheme in listen endpoint url")
            display("Unknown scheme in listen endpoint url: {:?}", scheme)
        }
    }
}

impl FromStr for ListenEndpoint {
    type Err = ParseListenEndpointError;

    fn from_str(s: &str) -> Result<ListenEndpoint, ParseListenEndpointError> {
        let url = match url::UrlParser::new().scheme_type_mapper(protocol::scheme_type_mapper)
                                             .parse(s) {
            Ok(url) => url,
            Err(e) => return Err(ParseListenEndpointError::BadUrl(e)),
        };
        match &url.scheme[..] {
            "tcp-listen" => {
                if let Some(q) = url.query {
                    return Err(ParseListenEndpointError::UnexpectedQuery(q));
                }
                if let Some(f) = url.fragment {
                    return Err(ParseListenEndpointError::UnexpectedFragment(f));
                }
                match url.scheme_data {
                    url::SchemeData::NonRelative(..) => panic!("scheme_type_mapper should not have returned this."),
                    url::SchemeData::Relative(rsd) => {
                        if rsd.username != "" {
                            return Err(ParseListenEndpointError::UnexpectedUsername(rsd.username));
                        }
                        if rsd.password.is_some() {
                            // Don't return the password in the error.
                            return Err(ParseListenEndpointError::UnexpectedPassword);
                        }
                        if !(rsd.path.len() == 1 && &rsd.path[0] == "") {
                            return Err(ParseListenEndpointError::UnexpectedPath(rsd.path));
                        }
                        let port = rsd.port.unwrap_or(0);
                        match rsd.host {
                            url::Host::Domain(s) => {
                                let mut iter = match (&s[..], port).to_socket_addrs() {
                                    Ok(iter) => iter,
                                    Err(e) => return Err(ParseListenEndpointError::ParseAddr(e)),
                                };
                                match (iter.next(), iter.next()) {
                                    (Some(a0), Some(a1)) => return Err(ParseListenEndpointError::MultipleAddrs(SocketAddr(a0), SocketAddr(a1))),
                                    (Some(a), None) => Ok(ListenEndpoint::Tcp(SocketAddr(a))),
                                    _ => return Err(ParseListenEndpointError::MissingAddr),
                                }
                            },
                            url::Host::Ipv4(ipv4_addr) => Ok(ListenEndpoint::Tcp(SocketAddr(
                                    net::SocketAddr::new(IpAddr::V4(ipv4_addr), port)
                            ))),
                            url::Host::Ipv6(ipv6_addr) => Ok(ListenEndpoint::Tcp(SocketAddr(
                                    net::SocketAddr::new(IpAddr::V6(ipv6_addr), port)
                            ))),
                        }
                    },
                }
            },
            _ => return Err(ParseListenEndpointError::UnknownScheme(url.scheme)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::net;

    use socket_addr::SocketAddr;

    use listen_endpoint::{ListenEndpoint, ToListenEndpoints};

    #[test]
    fn parse_listen_endpoint() {
        let s = &["tcp-listen://1.2.3.4:45666"][..];
        let mut listen_endpoints = s.to_listen_endpoints();
        let listen_endpoint = unwrap_result!(unwrap_option!(listen_endpoints.next(), "Expected at least one listen endpoint"));
        assert_eq!(listen_endpoint, ListenEndpoint::Tcp(SocketAddr(
            net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 45666)
        )));
        if let Some(res) = listen_endpoints.next() {
            panic!("Did not expect a second listen endpoint: {:?}", res);
        }
    }
}

