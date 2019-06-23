// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

//! Light client logic and implementation.
//!
//! A "light" client stores very little chain-related data locally
//! unlike a full node, which stores all blocks, headers, receipts, and more.
//!
//! This enables the client to have a much lower resource footprint in
//! exchange for the cost of having to ask the network for state data
//! while responding to queries. This makes a light client unsuitable for
//! low-latency applications, but perfectly suitable for simple everyday
//! use-cases like sending transactions from a personal account.
//!
//! The light client performs a header-only sync, doing verification and pruning
//! historical blocks. Upon pruning, batches of 2048 blocks have a number => (hash, TD)
//! mapping sealed into "canonical hash tries" which can later be used to verify
//! historical block queries from peers.

#![deny(missing_docs)]

pub mod cache;
pub mod cht;
pub mod client;
pub mod net;
pub mod on_demand;
pub mod provider;
pub mod transaction_queue;

mod types;

pub use self::cache::Cache;
pub use self::provider::Provider;
pub use self::transaction_queue::TransactionQueue;
pub use types::request;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate log;

extern crate bincode;
extern crate ethcore;
extern crate ethcore_bytes as bytes;
extern crate ethcore_io as io;
extern crate ethcore_network as network;
extern crate ethcore_transaction as transaction;
extern crate ethereum_types;
extern crate futures;
extern crate hashdb;
extern crate heapsize;
extern crate itertools;
extern crate memorydb;
extern crate parking_lot;
extern crate patricia_trie as trie;
extern crate plain_hasher;
extern crate rand;
extern crate rlp;
#[macro_use]
extern crate rlp_derive;
extern crate keccak_hash as hash;
extern crate kvdb;
extern crate memory_cache;
extern crate serde;
extern crate smallvec;
extern crate stats;
extern crate triehash;
extern crate vm;
#[macro_use]
extern crate error_chain;

#[cfg(test)]
extern crate kvdb_memorydb;
#[cfg(test)]
extern crate tempdir;
