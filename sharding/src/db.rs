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

//! Sharding database interface

use {Hash, ChunkHeader, ChunkBody, ShardId, Head};

pub trait Database: Send + Sync {
	fn load_header(&self, hash: &Hash) -> Option<ChunkHeader>;

	fn load_body(&self, hash: &Hash) -> Option<ChunkBody>;

	fn load_chunk(&self, hash: &Hash) -> (Option<ChunkHeader>, Option<ChunkBody>);

	fn load_head(&self, shard_id: &ShardId) -> Option<Head>;

	fn store_header(&self, header: &ChunkHeader);

	fn store_body(&self, hash: &Hash, body: &ChunkBody);

	fn store_chunk(&self, header: &ChunkHeader, body: &ChunkBody);

	fn store_head(&self, shard_id: &ShardId, head: &Head);
}