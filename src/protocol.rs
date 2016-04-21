//! Defines the protocols supported by this library through the `Protocol` type.

use std::fmt;
use std::error;
use std::str::FromStr;

use url;

/// Scheme type mapper function for transport protocol schemes defined by this crate. For use with
/// `url::UrlParser` from the `url` crate.
pub fn scheme_type_mapper(scheme: &str) -> url::SchemeType {
    match url::whatwg_scheme_type_mapper(scheme) {
        url::SchemeType::NonRelative => {
            match scheme {
                "tcp" => url::SchemeType::Relative(0),
                "utp" => url::SchemeType::Relative(0),
                "tcp-listen" => url::SchemeType::Relative(0),
                "utp-listen" => url::SchemeType::Relative(0),
                _ => url::SchemeType::NonRelative,
            }
        }
        st => st,
    }
}

/// Enum representing supported transport protocols
#[derive(Copy, Debug, Hash, Eq, PartialEq, Clone, RustcEncodable, RustcDecodable)]
pub enum Protocol {
    /// TCP protocol
    Tcp,
    /// uTP protocol
    Utp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Utp => write!(f, "utp"),
        }
    }
}

/// Errors returned by `FromStr::from_str` for `Protocol`.
#[derive(Copy, Debug, Hash, Eq, PartialEq, Clone, RustcEncodable, RustcDecodable)]
pub struct ProtocolParseError;

impl error::Error for ProtocolParseError {
    fn cause(&self) -> Option<&error::Error> {
        None
    }

    fn description(&self) -> &str {
        "Error parsing protocol string. Must be either \"tcp\" or \"utp\""
    }
}

impl fmt::Display for ProtocolParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error parsing protocol string. Must be either \"tcp\" or \"utp\"")
    }
}

impl FromStr for Protocol {
    type Err = ProtocolParseError;

    fn from_str(s: &str) -> Result<Protocol, ProtocolParseError> {
        if s == "tcp" || s == "TCP" {
            Ok(Protocol::Tcp)
        }
        else if s == "utp" || s == "UTP" {
            Ok(Protocol::Utp)
        }
        else {
            Err(ProtocolParseError)
        }
    }
}

