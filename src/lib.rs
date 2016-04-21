
//! # transport
//!
//! Streams based communications with transport abstraction and NAT traversal.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features,
        unconditional_recursion, unknown_lints, unsafe_code, unused, unused_allocation,
        unused_attributes, unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#[macro_use]
#[allow(unused_extern_crates)] // Needed as the crate is only used for macros
extern crate quick_error;
extern crate void;
extern crate socket_addr;
extern crate rustc_serialize;
extern crate nat_traversal;
extern crate w_result;
#[macro_use]
#[allow(unused_extern_crates)] // Needed as the crate is only used for macros
extern crate maidsafe_utilities;
#[macro_use]
extern crate log;
//extern crate loggerv;
extern crate byteorder;
extern crate crossbeam;
extern crate rand;
extern crate url;
extern crate lru_time_cache;
extern crate net2;

pub mod protocol;
pub mod endpoint;
pub mod listen_endpoint;
pub mod stream;
pub mod listener;
mod utils;
mod socket_utils;
mod rendezvous_info;

#[cfg(test)]
mod test_utils;

pub use protocol::Protocol;
pub use endpoint::{Endpoint, ToEndpoints};
pub use listen_endpoint::{ListenEndpoint, ToListenEndpoints};
pub use stream::{Stream, StreamInfo};
pub use listener::Listener;
pub use rendezvous_info::{PubRendezvousInfo, PrivRendezvousInfo};

