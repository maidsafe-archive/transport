//! Defines the `Endpoint` type and related items.

use std::iter;
use std::error;
use std::net;
use std::net::{IpAddr, ToSocketAddrs};
use std::fmt;
use std::io;
use std::str::FromStr;

use void::Void;
use socket_addr::SocketAddr;
use url;

use protocol;

/// Enum representing endpoint of supported protocols
#[derive(Copy, Debug, Eq, PartialEq, Hash, Clone, RustcEncodable, RustcDecodable)]
pub enum Endpoint {
    /// A TCP endpoint
    Tcp(SocketAddr),
    /// A uTP endpoint
    Utp(SocketAddr),
}

/// A trait for types that can be converted to an iterator of endpoints. This is similar to the
/// `ToSocketAddrs` trait from the standard library.
pub trait ToEndpoints {
    /// Errors that can occur when parsing the next endpoint
    type Err: error::Error + Send + 'static;

    /// The iterator returned by `to_endpoints`
    type Iter: Iterator<Item=Result<Endpoint, Self::Err>>;

    /// Returns an iterator that yields a sequence of endpoints (or errors).
    fn to_endpoints(&self) -> Self::Iter;
}

impl ToEndpoints for Endpoint {
    type Err = Void;
    type Iter = iter::Once<Result<Endpoint, Void>>;

    fn to_endpoints(&self) -> iter::Once<Result<Endpoint, Void>> {
        iter::once(Ok(*self))
    }
}

impl ToEndpoints for str {
    type Err = ParseEndpointError;
    type Iter = iter::Once<Result<Endpoint, ParseEndpointError>>;

    fn to_endpoints(&self) -> iter::Once<Result<Endpoint, ParseEndpointError>> {
        iter::once(Endpoint::from_str(self))
    }
}

impl<'a, T: ToEndpoints + ?Sized> ToEndpoints for &'a T {
    type Err = T::Err;
    type Iter = T::Iter;

    fn to_endpoints(&self) -> T::Iter {
        (*self).to_endpoints()
    }
}

/// Iterator returned when `ToEndpoints::to_endpoints` is called on a slice.
pub struct SliceEndpointsIter<'a, E: ToEndpoints + 'a> {
    slice: &'a [E],
    iter: Option<E::Iter>,
}

impl<'a, E: ToEndpoints + 'a> ToEndpoints for &'a [E] {
    type Iter = SliceEndpointsIter<'a, E>;
    type Err = E::Err;

    fn to_endpoints(&self) -> SliceEndpointsIter<'a, E> {
        match self.len() {
            0 => SliceEndpointsIter {
                slice: &[],
                iter: None,
            },
            _ => SliceEndpointsIter {
                slice: &self[1..],
                iter: Some(self[0].to_endpoints()),
            },
        }
    }
}

impl<'a, E: ToEndpoints + 'a> Iterator for SliceEndpointsIter<'a, E> {
    type Item = Result<Endpoint, E::Err>;

    fn next(&mut self) -> Option<Result<Endpoint, E::Err>> {
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
                    self.iter = Some(self.slice[0].to_endpoints());
                    self.slice = &self.slice[1..];
                },
            }
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Endpoint::Tcp(addr) => write!(f, "tcp://{}/", addr),
            Endpoint::Utp(addr) => write!(f, "utp://{}/", addr),
        }
    }
}

quick_error! {
    /// Errors returned by `FromStr::from_str` when parsing an `Endpoint`
    #[derive(Debug)]
    pub enum ParseEndpointError {
        /// Error parsing url
        BadUrl(err: url::ParseError) {
            description("Error parsing url")
            display("Error parsing url: {}", err)
            cause(err)
        }
        /// Endpoint url contains unexpected query
        UnexpectedQuery(query: String) {
            description("Endpoint url contains unexpected query")
            display("Endpoint url contains unexpected query: {:?}", query)
        }
        /// Endpoint url contains unexpected fragment")
        UnexpectedFragment(fragment: String) {
            description("Endpoint url contains unexpected fragment")
            display("Endpoint url contains unexpected fragment: {:?}", fragment)
        }
        /// Endpoint url contains unexpected username
        UnexpectedUsername(username: String) {
            description("Endpoint url contains unexpected username")
            display("Endpoint url contains unexpected username: {:?}", username)
        }
        /// Endpoint url contains unexpected password
        UnexpectedPassword {
            description("Endpoint url contains unexpected password")
        }
        /// Endpoint url contains unexpected path
        UnexpectedPath(path: Vec<String>) {
            description("Endpoint url contains unexpected path")
            display("Endpoint url contains unexpected path: {:?}", path)
        }
        /// Endpoint url is missing a port number
        MissingPort {
            description("Endpoint url is missing a port number")
        }
        /// Failed to parse the address of the endpoint url
        ParseAddr(err: io::Error) {
            description("Failed to parse the address of the endpoint url")
            display("Failed to parse the address of the endpoint url: {}", err)
            cause(err)
        }
        /// Endpoint url is missing the address
        MissingAddr {
            description("Endpoint url is missing the address")
        }
        /// Multiple addresses were parsed from the endpoint url
        MultipleAddrs(a0: SocketAddr, a1: SocketAddr) {
            description("Multiple addresses were parsed from the endpoint url")
            display("Multiple addresses were parsed from the endpoint url: {} and {}", a0, a1)
        }
        /// Unknown scheme in endpoint url
        UnknownScheme(scheme: String) {
            description("Unknown scheme in endpoint url")
            display("Unknown scheme in endpoint url: {:?}", scheme)
        }
    }
}

impl FromStr for Endpoint {
    type Err = ParseEndpointError;

    fn from_str(s: &str) -> Result<Endpoint, ParseEndpointError> {
        let url = match url::UrlParser::new().scheme_type_mapper(protocol::scheme_type_mapper)
                                             .parse(s) {
            Ok(url) => url,
            Err(e) => return Err(ParseEndpointError::BadUrl(e)),
        };
        match &url.scheme[..] {
            "tcp" => {
                if let Some(q) = url.query {
                    return Err(ParseEndpointError::UnexpectedQuery(q));
                }
                if let Some(f) = url.fragment {
                    return Err(ParseEndpointError::UnexpectedFragment(f));
                }
                match url.scheme_data {
                    url::SchemeData::NonRelative(..) => panic!("scheme_type_mapper should not have returned this."),
                    url::SchemeData::Relative(rsd) => {
                        if rsd.username != "" {
                            return Err(ParseEndpointError::UnexpectedUsername(rsd.username));
                        }
                        if rsd.password.is_some() {
                            // Don't return the password in the error.
                            return Err(ParseEndpointError::UnexpectedPassword);
                        }
                        if !(rsd.path.len() == 1 && &rsd.path[0] == "") {
                            return Err(ParseEndpointError::UnexpectedPath(rsd.path));
                        }
                        let port = match rsd.port {
                            Some(port) => port,
                            None => return Err(ParseEndpointError::MissingPort),
                        };
                        match rsd.host {
                            url::Host::Domain(s) => {
                                let mut iter = match (&s[..], port).to_socket_addrs() {
                                    Ok(iter) => iter,
                                    Err(e) => return Err(ParseEndpointError::ParseAddr(e)),
                                };
                                match (iter.next(), iter.next()) {
                                    (Some(a0), Some(a1)) => return Err(ParseEndpointError::MultipleAddrs(SocketAddr(a0), SocketAddr(a1))),
                                    (Some(a), None) => Ok(Endpoint::Tcp(SocketAddr(a))),
                                    _ => return Err(ParseEndpointError::MissingAddr),
                                }
                            },
                            url::Host::Ipv4(ipv4_addr) => Ok(Endpoint::Tcp(SocketAddr(
                                    net::SocketAddr::new(IpAddr::V4(ipv4_addr), port)
                            ))),
                            url::Host::Ipv6(ipv6_addr) => Ok(Endpoint::Tcp(SocketAddr(
                                    net::SocketAddr::new(IpAddr::V6(ipv6_addr), port)
                            ))),
                        }
                    },
                }
            },
            _ => return Err(ParseEndpointError::UnknownScheme(url.scheme)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::net;

    use socket_addr::SocketAddr;

    use endpoint::{Endpoint, ToEndpoints};

    #[test]
    fn parse_endpoint() {
        let s = &["tcp://192.168.0.1:45666"][..];
        let mut endpoints = s.to_endpoints();
        let endpoint = unwrap_result!(unwrap_option!(endpoints.next(), "Expected at least one endpoint"));
        assert_eq!(endpoint, Endpoint::Tcp(SocketAddr(
            net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 45666)
        )));
        if let Some(res) = endpoints.next() {
            panic!("Did not expect a second endpoint: {:?}", res);
        }
    }
}

