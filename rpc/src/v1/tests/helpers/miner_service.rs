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

//! Test implementation of miner service.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use bytes::Bytes;
use ethcore::account_provider::SignError as AccountError;
use ethcore::block::{Block, IsBlock, SealedBlock};
use ethcore::client::{EngineInfo, Nonce, PrepareOpenBlock, StateClient};
use ethcore::engines::EthEngine;
use ethcore::error::Error;
use ethcore::header::{BlockNumber, Header};
use ethcore::ids::BlockId;
use ethcore::miner::{AuthoringParams, MinerService};
use ethcore::receipt::{Receipt, RichReceipt};
use ethereum_types::{Address, H256, U256};
use miner::pool::local_transactions::Status as LocalTransactionStatus;
use miner::pool::{verifier, QueueStatus, VerifiedTransaction};
use parking_lot::{Mutex, RwLock};
use transaction::{self, PendingTransaction, SignedTransaction, UnverifiedTransaction};
use txpool;

/// Test miner service.
pub struct TestMinerService {
	/// Imported transactions.
	pub imported_transactions: Mutex<Vec<SignedTransaction>>,
	/// Pre-existed pending transactions
	pub pending_transactions: Mutex<HashMap<H256, SignedTransaction>>,
	/// Pre-existed local transactions
	pub local_transactions: Mutex<BTreeMap<H256, LocalTransactionStatus>>,
	/// Pre-existed pending receipts
	pub pending_receipts: Mutex<BTreeMap<H256, Receipt>>,
	/// Next nonces.
	pub next_nonces: RwLock<HashMap<Address, U256>>,
	/// Password held by Engine.
	pub password: RwLock<String>,

	authoring_params: RwLock<AuthoringParams>,
}

impl Default for TestMinerService {
	fn default() -> TestMinerService {
		TestMinerService {
			imported_transactions: Mutex::new(Vec::new()),
			pending_transactions: Mutex::new(HashMap::new()),
			local_transactions: Mutex::new(BTreeMap::new()),
			pending_receipts: Mutex::new(BTreeMap::new()),
			next_nonces: RwLock::new(HashMap::new()),
			password: RwLock::new(String::new()),
			authoring_params: RwLock::new(AuthoringParams {
				author: Address::zero(),
				gas_range_target: (12345.into(), 54321.into()),
				extra_data: vec![1, 2, 3, 4],
			}),
		}
	}
}

impl TestMinerService {
	/// Increments nonce for given address.
	pub fn increment_nonce(&self, address: &Address) {
		let mut next_nonces = self.next_nonces.write();
		let nonce = next_nonces.entry(*address).or_insert_with(|| 0.into());
		*nonce = *nonce + 1.into();
	}
}

impl StateClient for TestMinerService {
	// State will not be used by test client anyway, since all methods that accept state are mocked
	type State = ();

	fn latest_state(&self) -> Self::State {
		()
	}

	fn state_at(&self, _id: BlockId) -> Option<Self::State> {
		Some(())
	}
}

impl EngineInfo for TestMinerService {
	fn engine(&self) -> &EthEngine {
		unimplemented!()
	}
}

impl MinerService for TestMinerService {
	type State = ();

	fn pending_state(&self, _latest_block_number: BlockNumber) -> Option<Self::State> {
		None
	}

	fn pending_block_header(&self, _latest_block_number: BlockNumber) -> Option<Header> {
		None
	}

	fn pending_block(&self, _latest_block_number: BlockNumber) -> Option<Block> {
		None
	}

	fn authoring_params(&self) -> AuthoringParams {
		self.authoring_params.read().clone()
	}

	fn set_author(&self, author: Address, password: Option<String>) -> Result<(), AccountError> {
		self.authoring_params.write().author = author;
		if let Some(password) = password {
			*self.password.write() = password;
		}
		Ok(())
	}

	fn set_extra_data(&self, extra_data: Bytes) {
		self.authoring_params.write().extra_data = extra_data;
	}

	fn set_gas_range_target(&self, target: (U256, U256)) {
		self.authoring_params.write().gas_range_target = target;
	}

	/// Imports transactions to transaction queue.
	fn import_external_transactions<C: Nonce + Sync>(
		&self,
		chain: &C,
		transactions: Vec<UnverifiedTransaction>,
	) -> Vec<Result<(), transaction::Error>> {
		// lets assume that all txs are valid
		let transactions: Vec<_> = transactions
			.into_iter()
			.map(|tx| SignedTransaction::new(tx).unwrap())
			.collect();
		self.imported_transactions
			.lock()
			.extend_from_slice(&transactions);

		for sender in transactions.iter().map(|tx| tx.sender()) {
			let nonce = self.next_nonce(chain, &sender);
			self.next_nonces.write().insert(sender, nonce);
		}

		transactions.iter().map(|_| Ok(())).collect()
	}

	/// Imports transactions to transaction queue.
	fn import_own_transaction<C: Nonce + Sync>(
		&self,
		chain: &C,
		pending: PendingTransaction,
	) -> Result<(), transaction::Error> {
		// keep the pending nonces up to date
		let sender = pending.transaction.sender();
		let nonce = self.next_nonce(chain, &sender);
		self.next_nonces.write().insert(sender, nonce);

		// lets assume that all txs are valid
		self.imported_transactions.lock().push(pending.transaction);

		Ok(())
	}

	/// Called when blocks are imported to chain, updates transactions queue.
	fn chain_new_blocks<C>(
		&self,
		_chain: &C,
		_imported: &[H256],
		_invalid: &[H256],
		_enacted: &[H256],
		_retracted: &[H256],
		_is_internal: bool,
	) {
		unimplemented!();
	}

	/// New chain head event. Restart mining operation.
	fn update_sealing<C>(&self, _chain: &C) {
		unimplemented!();
	}

	fn work_package<C: PrepareOpenBlock>(
		&self,
		chain: &C,
	) -> Option<(H256, BlockNumber, u64, U256)> {
		let params = self.authoring_params();
		let open_block =
			chain.prepare_open_block(params.author, params.gas_range_target, params.extra_data);
		let closed = open_block.close();
		let header = closed.header();

		Some((
			header.hash(),
			header.number(),
			header.timestamp(),
			*header.difficulty(),
		))
	}

	fn transaction(&self, hash: &H256) -> Option<Arc<VerifiedTransaction>> {
		self.pending_transactions
			.lock()
			.get(hash)
			.cloned()
			.map(|tx| Arc::new(VerifiedTransaction::from_pending_block_transaction(tx)))
	}

	fn remove_transaction(&self, hash: &H256) -> Option<Arc<VerifiedTransaction>> {
		self.pending_transactions
			.lock()
			.remove(hash)
			.map(|tx| Arc::new(VerifiedTransaction::from_pending_block_transaction(tx)))
	}

	fn pending_transactions(&self, _best_block: BlockNumber) -> Option<Vec<SignedTransaction>> {
		Some(self.pending_transactions.lock().values().cloned().collect())
	}

	fn local_transactions(&self) -> BTreeMap<H256, LocalTransactionStatus> {
		self.local_transactions
			.lock()
			.iter()
			.map(|(hash, stats)| (*hash, stats.clone()))
			.collect()
	}

	fn ready_transactions<C>(&self, _chain: &C) -> Vec<Arc<VerifiedTransaction>> {
		self.queued_transactions()
	}

	fn queued_transactions(&self) -> Vec<Arc<VerifiedTransaction>> {
		self.pending_transactions
			.lock()
			.values()
			.cloned()
			.map(|tx| Arc::new(VerifiedTransaction::from_pending_block_transaction(tx)))
			.collect()
	}

	fn pending_receipt(&self, _best_block: BlockNumber, hash: &H256) -> Option<RichReceipt> {
		// Not much point implementing this since the logic is complex and the only thing it relies on is pending_receipts, which is already tested.
		self.pending_receipts(0)
			.unwrap()
			.get(hash)
			.map(|r| RichReceipt {
				transaction_hash: Default::default(),
				transaction_index: Default::default(),
				cumulative_gas_used: r.gas_used.clone(),
				gas_used: r.gas_used.clone(),
				contract_address: None,
				logs: r.logs.clone(),
				log_bloom: r.log_bloom,
				outcome: r.outcome.clone(),
			})
	}

	fn pending_receipts(&self, _best_block: BlockNumber) -> Option<BTreeMap<H256, Receipt>> {
		Some(self.pending_receipts.lock().clone())
	}

	fn next_nonce<C: Nonce + Sync>(&self, _chain: &C, address: &Address) -> U256 {
		self.next_nonces
			.read()
			.get(address)
			.cloned()
			.unwrap_or_default()
	}

	fn is_currently_sealing(&self) -> bool {
		false
	}

	fn queue_status(&self) -> QueueStatus {
		QueueStatus {
			options: verifier::Options {
				minimal_gas_price: 0x1312d00.into(),
				block_gas_limit: 5_000_000.into(),
				tx_gas_limit: 5_000_000.into(),
			},
			status: txpool::LightStatus {
				mem_usage: 1_000,
				transaction_count: 52,
				senders: 1,
			},
			limits: txpool::Options {
				max_count: 1_024,
				max_per_sender: 16,
				max_mem_usage: 5_000,
			},
		}
	}

	/// Submit `seal` as a valid solution for the header of `pow_hash`.
	/// Will check the seal, but not actually insert the block into the chain.
	fn submit_seal(&self, _pow_hash: H256, _seal: Vec<Bytes>) -> Result<SealedBlock, Error> {
		unimplemented!();
	}

	fn sensible_gas_price(&self) -> U256 {
		20_000_000_000u64.into()
	}

	fn sensible_gas_limit(&self) -> U256 {
		0x5208.into()
	}
}
