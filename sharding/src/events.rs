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

//! Sharding state event manager

use std::sync::Weak;
use std::collections::VecDeque;
use futures::{self, task, Async};

use {Head, ShardId};

#[derive(Clone, Debug)]
pub enum Event {
	NewHead {
		active_shard: ShardId,
		head: Head,
	},
	ActiveShardChanged {
		old_shard: ShardId,
		new_shard: ShardId
	},
}

pub struct Error;

pub type ResponseSink = futures::Sink<SinkItem=Event, SinkError=Error>;

pub trait EventHandler : Send + Sync {
	fn handle(&self, event: &Event, response: &mut ResponseSink);
}

#[derive(Default)]
pub struct EventManager {
	handlers: Vec<Weak<EventHandler>>,
}

impl EventManager {

	pub fn add_handler(&mut self, handler: Weak<EventHandler>) {
		self.handlers.push(handler)
	}

	pub fn dispatch(&self, event: Event) {
		let mut events = EventDeque::new(vec![event]);

		while let Some(next_event) = events.pop_front() {
			for handler_ref in self.handlers.iter() {
				if let Some(handler) = handler_ref.upgrade() {
					handler.handle(&next_event, &mut events);
				}
			}
		}
	}
}

pub struct EventDeque(VecDeque<Event>);

impl EventDeque {
	pub fn new<I: IntoIterator<Item=Event>>(i: I) -> Self {
		let mut vecdeque = VecDeque::new();
		let mut iter = i.into_iter();
		while let Some(next) = iter.next() {
			vecdeque.push_back(next)
		}

		EventDeque(vecdeque)
	}

	pub fn pop_front(&mut self) -> Option<Event> {
		self.0.pop_front()
	}
}

impl futures::Sink for EventDeque {
	type SinkItem = Event;
	type SinkError = Error;

	fn poll_ready(&mut self, _: &mut task::Context) -> Result<Async<()>, Self::SinkError> {
		Ok(Async::Ready(()))
	}

	fn start_send(&mut self, item: Self::SinkItem) -> Result<(), Self::SinkError> {
		self.0.push_back(item);
		Ok(())
	}

	fn poll_flush(&mut self, _: &mut task::Context) -> Result<Async<()>, Self::SinkError> {
		Ok(Async::Ready(()))
	}

	fn poll_close(&mut self, _: &mut task::Context) -> Result<Async<()>, Self::SinkError> {
		Ok(Async::Ready(()))
	}
}