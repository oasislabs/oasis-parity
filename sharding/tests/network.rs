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

extern crate sharding_client;
extern crate parking_lot;

mod test_db;

use std::sync::Arc;

use sharding_client::{Database, Message, MessagePayload, State as ShardingState, Head as ShardingHead};

use test_db::TestDb;

fn test_sharding_state() -> Arc<ShardingState> {
	let db = Box::new(TestDb::default());
	db.store_head(&128, &ShardingHead::new(0, 131211));

	Arc::new(ShardingState::new(128, db))
}

#[test]
fn peer_accepted() {
	let mut virtual_sink = Vec::new();

	let client = sharding_client::NetworkClient::new(test_sharding_state());

	client.message(
		Message {
			peer_id: 1,
			payload: MessagePayload::Status {
				shard_id: 128,
				protocol_version: 1,
				head_hash: 1,
				head_height: 1,
			}
		},
		&mut virtual_sink,
	).expect("impossible error");

	assert_eq!(virtual_sink.len(), 1,
		"There should be status response for status message");
	assert_eq!(client.active_peers(), 1,
		"Peer should be accepted and increase active peers because it is on the same shard_id");
}

#[test]
fn peer_dropped() {
	let mut virtual_sink = Vec::new();

	let client = sharding_client::NetworkClient::new(test_sharding_state());

	client.message(
		Message {
			peer_id: 1,
			payload: MessagePayload::Status {
				shard_id: 156,
				protocol_version: 1,
				head_hash: 1,
				head_height: 1,
			}
		},
		&mut virtual_sink,
	).expect("impossible error");

	assert_eq!(virtual_sink.len(), 1,
		"There should be disconnect response for status message");
	assert_eq!(&virtual_sink[0], &sharding_client::disconnect_message(1));
	assert_eq!(client.active_peers(), 0,
		"Peer should not be accepted because sharding client is on another shard");
}