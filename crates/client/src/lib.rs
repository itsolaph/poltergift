//! Poltergift client library: wallet storage, round state decoding, ring signing and the
//! transactions for every round operation.

pub mod client;
pub mod scan;
pub mod state;
pub mod store;

pub use client::{Finalized, Payout, PoltergiftClient, RoundParams};
pub use ootle_rs::provider::IndexerTrust;
pub use scan::OwnedOutput;
pub use state::RoundState;
pub use store::{MemberRecord, Store};
