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

//! Sharding main chain handler

use std::sync::{Weak, Arc};

use ethereum_types::H256;
use ethcore::client::{BlockChainClient, ChainNotify, Client};
use ethcore::BlockReceipts;
use rlp::Rlp;
use bytes::Bytes;

use {Head, State};

pub struct ChainHandler {
	state: Arc<State>,
	client: Weak<BlockChainClient>,
}

impl ChainHandler {
	pub fn new(
		client: Weak<BlockChainClient>,
		state: Arc<State>
	) -> Self {
		ChainHandler {
			client: client,
			state: state,
		}
	}
}

impl ChainNotify for ChainHandler {
	fn new_blocks(
		&self,
		mut imported: Vec<H256>,
		_invalid: Vec<H256>,
		_enacted: Vec<H256>,
		_retracted: Vec<H256>,
		_sealed: Vec<H256>,
		// Block bytes.
		_proposed: Vec<Bytes>,
		_duration: u64,
	) {
		let client = match self.client.upgrade() {
			Some(c) => c,
			_ => { return; }
		};

		for hash in imported.drain(..) {
			if let Some(receipts_bytes) = client.block_receipts(&hash) {
				let _block_receipts = Rlp::new(&receipts_bytes[..]).as_val::<BlockReceipts>();

				// todo: proper crawl events here
				self.state.new_head(Head::new(1, 1));
			} else {
				warn!("Missing receipts for {}", &hash);
			}
		}
	}
}

pub fn setup(state: Arc<State>, client: Arc<Client>) -> Arc<ChainHandler> {
	let chain_handler = Arc::new(
		ChainHandler::new(Arc::downgrade(&client) as Weak<BlockChainClient>, state)
	);

	client.add_notify(chain_handler.clone());

	chain_handler
}