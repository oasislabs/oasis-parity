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

//! Web3 rpc interface.
use jsonrpc_core::Result;

use v1::types::{Bytes, H256};

build_rpc_trait! {
	/// Web3 rpc interface.
	pub trait Web3 {
		/// Returns current client version.
		#[rpc(name = "web3_clientVersion")]
		fn client_version(&self) -> Result<String>;

		/// Returns sha3 of the given data
		#[rpc(name = "web3_sha3")]
		fn sha3(&self, Bytes) -> Result<H256>;
	}
}
