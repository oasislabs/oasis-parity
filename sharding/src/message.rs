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

//! Sharding message format

use common::{PeerId, ShardId, ProtocolVersion, Hash, Height};

#[derive(PartialEq, Debug, Clone)]
pub struct Message {
	pub peer_id: PeerId,
	pub payload: MessagePayload,
}

#[derive(PartialEq, Debug, Clone)]
pub enum MessagePayload {
	Status {
		protocol_version: ProtocolVersion,
		shard_id: ShardId,
		head_height: Height,
		head_hash: Hash,
	},
	Disconnect,
}

pub fn disconnect(peer_id: PeerId) -> Message {
	Message {
		peer_id: peer_id,
		payload: MessagePayload::Disconnect,
	}
}