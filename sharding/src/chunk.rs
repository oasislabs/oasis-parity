// Copyright 2015-2017 Parity Technologies (UK) Ltd.
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

//! Sharding chunks data structures

use common;

#[derive(Clone)]
pub struct Header {
	shard_id: common::ShardId,
	period_id: common::PeriodId,
	root: common::Hash,
}

#[derive(Clone)]
pub struct Body(Vec<u8>);

impl Header {
	pub fn hash(&self) -> common::Hash {
		// todo: keccak
		0
	}

	pub fn shard_id(&self) -> &common::ShardId {
		&self.shard_id
	}

	pub fn peroid_id(&self) -> &common::PeriodId {
		&self.period_id
	}

	pub fn root(&self) -> &common::Hash {
		&self.root
	}
}

impl Body {
	pub fn as_bytes(&self) -> &[u8] {
		&self.0[..]
	}

	pub fn into_bytes(self) -> Vec<u8> {
		self.0
	}

	pub fn root(&self) -> common::Hash {
		// todo: merkle
		0
	}
}