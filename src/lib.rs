#![doc = include_str!("../README.md")]
//!
//! ## Minimal API example
//!
//! ```no_run
//! use std::net::Ipv4Addr;
//!
//! use bpflink::{Link, PeerAddr};
//!
//! # async fn example() -> bpflink::Result<()> {
//! let link = Link::builder()
//!     .interface("en0")
//!     .local_ipv4(Ipv4Addr::new(192, 0, 2, 1))
//!     .service_ports([40000, 40001])
//!     .build()
//!     .await?;
//!
//! let listener = link.listen(40000).await?;
//! let stream = link
//!     .connect(
//!         PeerAddr {
//!             ip: Ipv4Addr::new(192, 0, 2, 2).into(),
//!         },
//!         40000,
//!     )
//!     .await?;
//! # let _ = (listener, stream);
//! # Ok(())
//! # }
//! ```
//!
//! Runtime support is currently implemented for macOS and Linux. Other
//! platforms return [`Error::UnsupportedPlatform`] from the runtime builder.

mod bpf;
pub mod diagnostics;
mod error;
mod link;
mod runtime;
pub mod socket;
mod stack;
mod transport;

pub use error::{Error, Result};
pub use link::{parse_scoped_ip, Link, LinkBuilder, LinkConfig, LinkStats, PeerAddr};
pub use socket::{BpfListener, BpfStream};
pub use transport::TransportMode;

#[cfg(feature = "test-util")]
pub use runtime::TestCommand;
