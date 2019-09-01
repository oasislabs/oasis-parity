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

//! Types used in the public API

extern crate ethcore_bytes as bytes;
extern crate ethereum_types;
extern crate ethjson;
extern crate rlp;
#[macro_use]
extern crate rlp_derive;
extern crate heapsize;
extern crate keccak_hash as hash;
#[macro_use]
extern crate serde_derive;
extern crate serde;

#[cfg(test)]
extern crate rustc_hex;

pub mod account_diff;
pub mod ancestry_action;
pub mod basic_account;
pub mod block_status;
pub mod blockchain_info;
pub mod call_analytics;
pub mod filter;
pub mod ids;
pub mod log_entry;
pub mod pruning_info;
pub mod receipt;
pub mod restoration_status;
pub mod security_level;
pub mod snapshot_manifest;
pub mod state_diff;
pub mod trace_filter;
pub mod tree_route;
pub mod verification_queue_info;

/// Type for block number.
pub type BlockNumber = u64;

// The following two methods are required because we're pinned to ethereum-types v0.3,
// which existed before 128-bit integers in Rust. Newer versions have `to_low_u128`.
// ref: https://github.com/paritytech/parity-common/blob/6283d8e/uint/src/uint.rs

pub fn u128_from_u256(val: ethereum_types::U256) -> u128 {
	let mut buf = [0; 16];
	for i in 0..buf.len() {
		buf[i] = val.byte(i);
	}
	u128::from_le_bytes(buf)
}

pub fn u256_from_u128(val: u128) -> ethereum_types::U256 {
	ethereum_types::U256::from_little_endian(&val.to_le_bytes())
}
