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

#![warn(missing_docs)]
#![cfg_attr(feature = "benches", feature(test))]

//! Ethcore library
//!
//! ### Rust version:
//! - nightly
//!
//! ### Supported platforms:
//! - OSX
//! - Linux
//!
//! ### Building:
//!
//! - Ubuntu 14.04 and later:
//!
//!   ```bash
//!
//!   # install rustup
//!   curl https://sh.rustup.rs -sSf | sh
//!
//!   # download and build parity
//!   git clone https://github.com/paritytech/parity
//!   cd parity
//!   cargo build --release
//!   ```
//!
//! - OSX:
//!
//!   ```bash
//!   # install rocksdb && rustup
//!   brew update
//!   curl https://sh.rustup.rs -sSf | sh
//!
//!   # download and build parity
//!   git clone https://github.com/paritytech/parity
//!   cd parity
//!   cargo build --release
//!   ```

// Recursion limit required because of
// error_chain foreign_links.
#![recursion_limit = "128"]

extern crate bloomchain;
extern crate bn;
extern crate byteorder;
pub extern crate common_types as types;
extern crate ethcore_bloom_journal as bloom_journal;
extern crate ethcore_bytes as bytes;
extern crate ethcore_crypto;
pub extern crate ethcore_transaction as transaction;
extern crate ethereum_types;
pub extern crate ethjson;
extern crate ethkey;
extern crate hashdb;
extern crate itertools;
extern crate lru_cache;
extern crate num_bigint;
extern crate num_integer;
extern crate num_traits;
mod num {
	pub use num_bigint::*;
	pub use num_integer::*;
	pub use num_traits::*;
}
extern crate ethabi;
extern crate heapsize;
extern crate keccak_hash as hash;
pub extern crate kvdb;
extern crate kvdb_memorydb;
extern crate memorydb;
extern crate parity_machine;
extern crate patricia_trie as trie;
#[cfg(test)]
extern crate rand;
pub extern crate rlp;
extern crate rlp_compress;
extern crate rustc_hex;
extern crate triehash;
extern crate unexpected;
extern crate util_error;
pub extern crate vm;

extern crate wasm;

extern crate failure;
pub extern crate journaldb;
extern crate memory_cache;
#[cfg(test)]
extern crate tempdir;

#[macro_use]
extern crate ethabi_derive;
#[macro_use]
extern crate ethabi_contract;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate macros;
#[macro_use]
extern crate rlp_derive;
#[macro_use]
extern crate serde_json;

#[cfg_attr(test, macro_use)]
extern crate evm;

#[macro_use]
pub mod views;

pub mod block;
pub mod db;
pub mod encoded;
pub mod engines;
pub mod error;
#[cfg(test)]
pub mod ethereum;
pub mod executed;
pub mod executive;
pub mod header;
pub mod machine;
pub mod mkvs;
pub mod pod_state;
pub mod spec;
pub mod state;
pub mod state_db;
pub mod trace;
/// Ext (Externalities) tracing
pub mod trace_ext;

pub mod account_db;
pub mod blockchain;
mod blooms;
mod builtin;
mod cache_manager;
mod externalities;
pub mod factory;
mod pod_account;

#[cfg(test)]
#[cfg(feature = "json-tests")]
mod json_tests;
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers;

pub use evm::CreateContractAddress;
pub use executive::contract_address;
pub use types::*;
