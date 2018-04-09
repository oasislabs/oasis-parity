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
extern crate futures;
extern crate parking_lot;

use self::sharding_client::{Event, EventHandler, EventError};
use self::parking_lot::RwLock;

#[derive(Default)]
pub struct TestEventHandler {
	pub store: RwLock<Vec<Event>>,
}

impl EventHandler for TestEventHandler {
	fn handle(&self, event: &Event, _response: &mut (self::futures::Sink<SinkItem=Event, SinkError=EventError> + 'static)) {
		self.store.write().push(event.clone());
	}
}