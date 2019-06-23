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

//! A map of subscribers.

use jsonrpc_macros::pubsub::{Sink, Subscriber, SubscriptionId};
use rand::{Rng, StdRng};
use std::collections::HashMap;
use std::{ops, str};
use v1::types::H64;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Id(H64);
impl str::FromStr for Id {
	type Err = String;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.starts_with("0x") {
			Ok(Id(s[2..].parse().map_err(|e| format!("{}", e))?))
		} else {
			Err("The id must start with 0x".into())
		}
	}
}
impl Id {
	pub fn as_string(&self) -> String {
		format!("0x{:?}", self.0)
	}
}

#[derive(Clone)]
pub struct Subscribers<T> {
	rand: StdRng,
	subscriptions: HashMap<Id, T>,
}

impl<T> Default for Subscribers<T> {
	fn default() -> Self {
		Subscribers {
			rand: StdRng::new().expect("Valid random source is required."),
			subscriptions: HashMap::new(),
		}
	}
}

impl<T> Subscribers<T> {
	/// Create a new Subscribers with given random source.
	#[cfg(test)]
	pub fn new_test() -> Self {
		Subscribers {
			rand: ::rand::SeedableRng::from_seed([0usize].as_ref()),
			subscriptions: HashMap::new(),
		}
	}

	fn next_id(&mut self) -> Id {
		let mut data = H64::default();
		self.rand.fill_bytes(&mut data.0);
		Id(data)
	}

	/// Insert new subscription and return assigned id.
	pub fn insert(&mut self, val: T) -> SubscriptionId {
		let id = self.next_id();
		debug!(target: "pubsub", "Adding subscription id={:?}", id);
		let s = id.as_string();
		self.subscriptions.insert(id, val);
		SubscriptionId::String(s)
	}

	/// Removes subscription with given id and returns it (if any).
	pub fn remove(&mut self, id: &SubscriptionId) -> Option<T> {
		trace!(target: "pubsub", "Removing subscription id={:?}", id);
		match *id {
			SubscriptionId::String(ref id) => match id.parse() {
				Ok(id) => self.subscriptions.remove(&id),
				Err(_) => None,
			},
			_ => None,
		}
	}
}

impl<T> Subscribers<Sink<T>> {
	/// Assigns id and adds a subscriber to the list.
	pub fn push(&mut self, sub: Subscriber<T>) {
		let id = self.next_id();
		if let Ok(sink) = sub.assign_id(SubscriptionId::String(id.as_string())) {
			debug!(target: "pubsub", "Adding subscription id={:?}", id);
			self.subscriptions.insert(id, sink);
		}
	}
}

impl<T, V> Subscribers<(Sink<T>, V)> {
	/// Assigns id and adds a subscriber to the list.
	pub fn push(&mut self, sub: Subscriber<T>, val: V) {
		let id = self.next_id();
		if let Ok(sink) = sub.assign_id(SubscriptionId::String(id.as_string())) {
			debug!(target: "pubsub", "Adding subscription id={:?}", id);
			self.subscriptions.insert(id, (sink, val));
		}
	}
}

impl<T> ops::Deref for Subscribers<T> {
	type Target = HashMap<Id, T>;

	fn deref(&self) -> &Self::Target {
		&self.subscriptions
	}
}
