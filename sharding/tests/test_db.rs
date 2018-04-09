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

extern crate parking_lot;
extern crate sharding_client;

use std::collections::HashMap;
use self::parking_lot::RwLock;

use self::sharding_client::{ChunkHeader, ChunkBody, Database, Hash, ShardId, Head};

#[derive(Default)]
pub struct TestDb {
	headers: RwLock<HashMap<Hash, ChunkHeader>>,
	bodies: RwLock<HashMap<Hash, ChunkBody>>,
	heads: RwLock<HashMap<ShardId, Head>>,
}

impl Database for TestDb {
	fn load_header(&self, hash: &Hash) -> Option<ChunkHeader> {
		self.headers.read().get(hash).cloned()
	}

	fn load_body(&self, hash: &Hash) -> Option<ChunkBody> {
		self.bodies.read().get(hash).cloned()
	}

	fn load_chunk(&self, hash: &Hash) -> (Option<ChunkHeader>, Option<ChunkBody>) {
		let headers = self.headers.read();
		let bodies = self.bodies.read();
		(headers.get(hash).cloned(), bodies.get(hash).cloned())
	}

	fn load_head(&self, shard_id: &ShardId) -> Option<Head> {
		self.heads.read().get(shard_id).cloned()
	}

	fn store_header(&self, header: &ChunkHeader) {
		self.headers.write().insert(header.hash(), header.clone());
	}

	fn store_body(&self, hash: &Hash, body: &ChunkBody) {
		self.bodies.write().insert(*hash, body.clone());
	}

	fn store_chunk(&self, header: &ChunkHeader, body: &ChunkBody) {
		let hash = header.hash();
		let mut headers = self.headers.write();
		let mut bodies = self.bodies.write();
		headers.insert(hash.clone(), header.clone());
		bodies.insert(hash.clone(), body.clone());
	}

	fn store_head(&self, shard_id: &ShardId, head: &Head) {
		self.heads.write().insert(shard_id.clone(), head.clone());
	}
}