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

extern crate ethcore;
extern crate sharding_client;
#[macro_use] extern crate assert_matches;

mod test_event_handler;
mod test_db;

use std::sync::Arc;

use test_event_handler::TestEventHandler;
use test_db::TestDb;

use sharding_client::{State as ShardingState, Head as ShardingHead, Event, Database};

fn test_sharding_state() -> Arc<ShardingState> {
	let db = Box::new(TestDb::default());
	db.store_head(&172, &ShardingHead::new(0, 131211));

	Arc::new(ShardingState::new(172, db))
}

#[test]
fn change_shard() {
	let test_state = test_sharding_state();
	let test_handler = Arc::new(TestEventHandler::default());
	test_state.add_event_handler(Arc::downgrade(&test_handler) as _);

	test_state.change_shard(173);

	let event = test_handler.store.write().pop();

	assert_matches!(
		event,
		Some(Event::ActiveShardChanged {
			old_shard: 172,
			new_shard: 173,
		})
	);

}