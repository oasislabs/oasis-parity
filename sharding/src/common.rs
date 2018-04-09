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

//! Sharding common types

pub type ShardId = u64;
pub type ProtocolVersion = u64;
pub type Height = u64;
pub type Hash = u64;
pub type PeerId = u64;
pub type PeriodId = u64;

pub const PROTOCOL_VERSION: ProtocolVersion = 1;

#[derive(Debug, Default, Clone)]
pub struct Head {
	height: Height,
	hash: Hash,
}

impl Head {
	pub fn new(height: Height, hash: Hash) -> Head {
		Head {
			height: height,
			hash: hash,
		}
	}

	pub fn height(&self) -> Height {
		self.height
	}

	pub fn hash(&self) -> &Hash {
		&self.hash
	}

	pub fn update(&mut self, new_height: Height, new_hash: Hash) {
		self.height = new_height;
		self.hash = new_hash;
	}
}