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

use std::time::{Instant, Duration};
use std::collections::{BTreeMap, HashSet, HashMap};
use std::sync::Arc;

use ansi_term::Colour;
use bytes::Bytes;
use engines::{EthEngine, Seal};
use error::{Error, ErrorKind, ExecutionError};
use ethcore_miner::gas_pricer::GasPricer;
use ethcore_miner::pool::{self, TransactionQueue, VerifiedTransaction, QueueStatus, PrioritizationStrategy};
use ethcore_miner::work_notify::NotifyWork;
use ethereum_types::{H256, U256, Address};
use parking_lot::{Mutex, RwLock};
use rayon::prelude::*;
use transaction::{
	self,
	Action,
	UnverifiedTransaction,
	SignedTransaction,
	PendingTransaction,
};
use using_queue::{UsingQueue, GetAction};

use account_provider::{AccountProvider, SignError as AccountError};
use block::{ClosedBlock, IsBlock, Block, SealedBlock};
use client::{
	BlockChain, ChainInfo, CallContract, BlockProducer, SealedBlockImporter, Nonce
};
use client::BlockId;
use executive::contract_address;
use header::{Header, BlockNumber};
use miner;
use miner::pool_client::{PoolClient, CachedNonceClient};
use receipt::{Receipt, RichReceipt};
use spec::Spec;
use state::State;
use storage::NullStorage;

/// Different possible definitions for pending transaction set.
#[derive(Debug, PartialEq)]
pub enum PendingSet {
	/// Always just the transactions in the queue. These have had only cheap checks.
	AlwaysQueue,
	/// Always just the transactions in the sealing block. These have had full checks but
	/// may be empty if the node is not actively mining or has no force_sealing enabled.
	AlwaysSealing,
	/// Takes from sealing if mining, from queue otherwise.
	SealingOrElseQueue,
}

/// Transaction queue penalization settings.
///
/// Senders of long-running transactions (above defined threshold)
/// will get lower priority.
#[derive(Debug, PartialEq, Clone)]
pub enum Penalization {
	/// Penalization in transaction queue is disabled
	Disabled,
	/// Penalization in transaction queue is enabled
	Enabled {
		/// Upper limit of transaction processing time before penalizing.
		offend_threshold: Duration,
	},
}

/// Initial minimal gas price.
///
/// Gas price should be later overwritten externally
/// for instance by a dynamic gas price mechanism or CLI parameter.
/// This constant controls the initial value.
const DEFAULT_MINIMAL_GAS_PRICE: u64 = 20_000_000_000;

/// Allowed number of skipped transactions when constructing pending block.
///
/// When we push transactions to pending block, some of the transactions might
/// get skipped because of block gas limit being reached.
/// This constant controls how many transactions we can skip because of that
/// before stopping attempts to push more transactions to the block.
/// This is an optimization that prevents traversing the entire pool
/// in case we have only a fraction of available block gas limit left.
const MAX_SKIPPED_TRANSACTIONS: usize = 8;

/// Configures the behaviour of the miner.
#[derive(Debug, PartialEq)]
pub struct MinerOptions {
	/// Force the miner to reseal, even when nobody has asked for work.
	pub force_sealing: bool,
	/// Reseal on receipt of new external transactions.
	pub reseal_on_external_tx: bool,
	/// Reseal on receipt of new local transactions.
	pub reseal_on_own_tx: bool,
	/// Reseal when new uncle block has been imported.
	pub reseal_on_uncle: bool,
	/// Minimum period between transaction-inspired reseals.
	pub reseal_min_period: Duration,
	/// Maximum period between blocks (enables force sealing after that).
	pub reseal_max_period: Duration,
	/// Whether we should fallback to providing all the queue's transactions or just pending.
	pub pending_set: PendingSet,
	/// How many historical work packages can we store before running out?
	pub work_queue_size: usize,
	/// Can we submit two different solutions for the same block and expect both to result in an import?
	pub enable_resubmission: bool,
	/// Create a pending block with maximal possible gas limit.
	/// NOTE: Such block will contain all pending transactions but
	/// will be invalid if mined.
	pub infinite_pending_block: bool,

	/// Strategy to use for prioritizing transactions in the queue.
	pub tx_queue_strategy: PrioritizationStrategy,
	/// Simple senders penalization.
	pub tx_queue_penalization: Penalization,
	/// Do we refuse to accept service transactions even if sender is certified.
	pub refuse_service_transactions: bool,
	/// Transaction pool limits.
	pub pool_limits: pool::Options,
	/// Initial transaction verification options.
	pub pool_verification_options: pool::verifier::Options,
}

impl Default for MinerOptions {
	fn default() -> Self {
		MinerOptions {
			force_sealing: false,
			reseal_on_external_tx: false,
			reseal_on_own_tx: true,
			reseal_on_uncle: false,
			reseal_min_period: Duration::from_secs(2),
			reseal_max_period: Duration::from_secs(120),
			pending_set: PendingSet::AlwaysQueue,
			work_queue_size: 20,
			enable_resubmission: true,
			infinite_pending_block: false,
			tx_queue_strategy: PrioritizationStrategy::GasPriceOnly,
			tx_queue_penalization: Penalization::Disabled,
			refuse_service_transactions: false,
			pool_limits: pool::Options {
				max_count: 8_192,
				max_per_sender: 81,
				max_mem_usage: 4 * 1024 * 1024,
			},
			pool_verification_options: pool::verifier::Options {
				minimal_gas_price: DEFAULT_MINIMAL_GAS_PRICE.into(),
				block_gas_limit: U256::max_value(),
				tx_gas_limit: U256::max_value(),
			},
		}
	}
}

/// Configurable parameters of block authoring.
#[derive(Debug, Default, Clone)]
pub struct AuthoringParams {
	/// Lower and upper bound of block gas limit that we are targeting
	pub gas_range_target: (U256, U256),
	/// Block author
	pub author: Address,
	/// Block extra data
	pub extra_data: Bytes,
}

struct SealingWork {
	queue: UsingQueue<ClosedBlock>,
	enabled: bool,
	next_allowed_reseal: Instant,
	next_mandatory_reseal: Instant,
	// block number when sealing work was last requested
	last_request: u64,
}

impl SealingWork {
	/// Are we allowed to do a non-mandatory reseal?
	fn reseal_allowed(&self) -> bool {
		Instant::now() > self.next_allowed_reseal
	}
}

/// Keeps track of transactions using priority queue and holds currently mined block.
/// Handles preparing work for "work sealing" or seals "internally" if Engine does not require work.
pub struct Miner {
	// NOTE [ToDr]  When locking always lock in this order!
	sealing: Mutex<SealingWork>,
	params: RwLock<AuthoringParams>,
	listeners: RwLock<Vec<Box<NotifyWork>>>,
	nonce_cache: RwLock<HashMap<Address, U256>>,
	gas_pricer: Mutex<GasPricer>,
	options: MinerOptions,
	// TODO [ToDr] Arc is only required because of price updater
	transaction_queue: Arc<TransactionQueue>,
	engine: Arc<EthEngine>,
	accounts: Option<Arc<AccountProvider>>,
}

impl Miner {
	/// Push listener that will handle new jobs
	pub fn add_work_listener(&self, notifier: Box<NotifyWork>) {
		self.listeners.write().push(notifier);
		self.sealing.lock().enabled = true;
	}

	/// Set a callback to be notified about imported transactions' hashes.
	pub fn add_transactions_listener(&self, f: Box<Fn(&[H256]) + Send + Sync>) {
		self.transaction_queue.add_listener(f);
	}

	/// Creates new instance of miner Arc.
	pub fn new(options: MinerOptions, gas_pricer: GasPricer, spec: &Spec, accounts: Option<Arc<AccountProvider>>) -> Self {
		let limits = options.pool_limits.clone();
		let verifier_options = options.pool_verification_options.clone();
		let tx_queue_strategy = options.tx_queue_strategy;

		Miner {
			sealing: Mutex::new(SealingWork {
				queue: UsingQueue::new(options.work_queue_size),
				enabled: options.force_sealing
					|| spec.engine.seals_internally().is_some(),
				next_allowed_reseal: Instant::now(),
				next_mandatory_reseal: Instant::now() + options.reseal_max_period,
				last_request: 0,
			}),
			params: RwLock::new(AuthoringParams::default()),
			listeners: RwLock::new(vec![]),
			gas_pricer: Mutex::new(gas_pricer),
			nonce_cache: RwLock::new(HashMap::with_capacity(1024)),
			options,
			transaction_queue: Arc::new(TransactionQueue::new(limits, verifier_options, tx_queue_strategy)),
			accounts,
			engine: spec.engine.clone(),
		}
	}

	/// Creates new instance of miner with given spec and accounts.
	///
	/// NOTE This should be only used for tests.
	pub fn new_for_tests(spec: &Spec, accounts: Option<Arc<AccountProvider>>) -> Miner {
		let minimal_gas_price = 0.into();
		Miner::new(MinerOptions {
			pool_verification_options: pool::verifier::Options {
				minimal_gas_price,
				block_gas_limit: U256::max_value(),
				tx_gas_limit: U256::max_value(),
			},
			reseal_min_period: Duration::from_secs(0),
			..Default::default()
		}, GasPricer::new_fixed(minimal_gas_price), spec, accounts)
	}

	/// Clear all pending block states
	pub fn clear(&self) {
		self.sealing.lock().queue.reset();
	}

	/// Updates transaction queue verification limits.
	///
	/// Limits consist of current block gas limit and minimal gas price.
	pub fn update_transaction_queue_limits(&self, block_gas_limit: U256) {
		trace!(target: "miner", "minimal_gas_price: recalibrating...");
		let txq = self.transaction_queue.clone();
		let mut options = self.options.pool_verification_options.clone();
		self.gas_pricer.lock().recalibrate(move |gas_price| {
			debug!(target: "miner", "minimal_gas_price: Got gas price! {}", gas_price);
			options.minimal_gas_price = gas_price;
			options.block_gas_limit = block_gas_limit;
			txq.set_verifier_options(options);
		});
	}

	/// Retrieves an existing pending block iff it's not older than given block number.
	///
	/// NOTE: This will not prepare a new pending block if it's not existing.
	/// See `map_pending_block` for alternative behaviour.
	fn map_existing_pending_block<F, T>(&self, f: F, latest_block_number: BlockNumber) -> Option<T> where
		F: FnOnce(&ClosedBlock) -> T,
	{
		self.sealing.lock().queue
			.peek_last_ref()
			.and_then(|b| {
				if b.block().header().number() > latest_block_number {
					Some(f(b))
				} else {
					None
				}
			})
	}

	fn pool_client<'a, C: 'a>(&'a self, chain: &'a C) -> PoolClient<'a, C> where
		C: BlockChain + CallContract,
	{
		PoolClient::new(
			chain,
			&self.nonce_cache,
			&*self.engine,
			self.accounts.as_ref().map(|x| &**x),
			self.options.refuse_service_transactions,
		)
	}

	/// Prepares new block for sealing including top transactions from queue.
	fn prepare_block<C>(&self, chain: &C) -> (ClosedBlock, Option<H256>) where
		C: BlockChain + CallContract + BlockProducer + Nonce + Sync,
	{
		trace_time!("prepare_block");
		let chain_info = chain.chain_info();

		// Open block
		let (mut open_block, original_work_hash) = {
			let mut sealing = self.sealing.lock();
			let last_work_hash = sealing.queue.peek_last_ref().map(|pb| pb.block().header().hash());
			let best_hash = chain_info.best_block_hash;

			// check to see if last ClosedBlock in would_seals is actually same parent block.
			// if so
			//   duplicate, re-open and push any new transactions.
			//   if at least one was pushed successfully, close and enqueue new ClosedBlock;
			//   otherwise, leave everything alone.
			// otherwise, author a fresh block.
			let mut open_block = match sealing.queue.pop_if(|b| b.block().header().parent_hash() == &best_hash) {
				Some(old_block) => {
					trace!(target: "miner", "prepare_block: Already have previous work; updating and returning");
					// add transactions to old_block
					chain.reopen_block(old_block)
				}
				None => {
					// block not found - create it.
					trace!(target: "miner", "prepare_block: No existing work - making new block");
					let params = self.params.read().clone();
					chain.prepare_open_block(
						params.author,
						params.gas_range_target,
						params.extra_data,
					)
				}
			};

			if self.options.infinite_pending_block {
				open_block.remove_gas_limit();
			}

			(open_block, last_work_hash)
		};

		let mut invalid_transactions = HashSet::new();
		let mut not_allowed_transactions = HashSet::new();
		let mut senders_to_penalize = HashSet::new();
		let block_number = open_block.block().header().number();

		let mut tx_count = 0usize;
		let mut skipped_transactions = 0usize;

		let client = self.pool_client(chain);
		let engine_params = self.engine.params();
		let min_tx_gas = self.engine.schedule(chain_info.best_block_number).tx_gas.into();
		let nonce_cap: Option<U256> = if chain_info.best_block_number + 1 >= engine_params.dust_protection_transition {
			Some((engine_params.nonce_cap_increment * (chain_info.best_block_number + 1)).into())
		} else {
			None
		};

		let pending: Vec<Arc<_>> = self.transaction_queue.pending(
			client.clone(),
			chain_info.best_block_number,
			chain_info.best_block_timestamp,
			nonce_cap,
		);

		let took_ms = |elapsed: &Duration| {
			elapsed.as_secs() * 1000 + elapsed.subsec_nanos() as u64 / 1_000_000
		};

		let block_start = Instant::now();
		debug!(target: "miner", "Attempting to push {} transactions.", pending.len());

		for tx in pending {
			let start = Instant::now();

			let transaction = tx.signed().clone();
			let hash = transaction.hash();
			let sender = transaction.sender();
			let mut storage = NullStorage::new();

			// Re-verify transaction again vs current state.
			let result = client.verify_signed(&transaction)
				.map_err(|e| e.into())
				.and_then(|_| {
					open_block.push_transaction(transaction, None)
				});

			let took = start.elapsed();

			// Check for heavy transactions
			match self.options.tx_queue_penalization {
				Penalization::Enabled { ref offend_threshold } if &took > offend_threshold => {
					senders_to_penalize.insert(sender);
					debug!(target: "miner", "Detected heavy transaction ({} ms). Penalizing sender.", took_ms(&took));
				},
				_ => {},
			}

			debug!(target: "miner", "Adding tx {:?} took {} ms", hash, took_ms(&took));
			match result {
				Err(Error(ErrorKind::Execution(ExecutionError::BlockGasLimitReached { gas_limit, gas_used, gas }), _)) => {
					debug!(target: "miner", "Skipping adding transaction to block because of gas limit: {:?} (limit: {:?}, used: {:?}, gas: {:?})", hash, gas_limit, gas_used, gas);

					// Penalize transaction if it's above current gas limit
					if gas > gas_limit {
						debug!(target: "txqueue", "[{:?}] Transaction above block gas limit.", hash);
						invalid_transactions.insert(hash);
					}

					// Exit early if gas left is smaller then min_tx_gas
					let gas_left = gas_limit - gas_used;
					if gas_left < min_tx_gas {
						debug!(target: "miner", "Remaining gas is lower than minimal gas for a transaction. Block is full.");
						break;
					}

					// Avoid iterating over the entire queue in case block is almost full.
					skipped_transactions += 1;
					if skipped_transactions > MAX_SKIPPED_TRANSACTIONS {
						debug!(target: "miner", "Reached skipped transactions threshold. Assuming block is full.");
						break;
					}
				},
				// Invalid nonce error can happen only if previous transaction is skipped because of gas limit.
				// If there is errornous state of transaction queue it will be fixed when next block is imported.
				Err(Error(ErrorKind::Execution(ExecutionError::InvalidNonce { expected, got }), _)) => {
					debug!(target: "miner", "Skipping adding transaction to block because of invalid nonce: {:?} (expected: {:?}, got: {:?})", hash, expected, got);
				},
				// already have transaction - ignore
				Err(Error(ErrorKind::Transaction(transaction::Error::AlreadyImported), _)) => {},
				Err(Error(ErrorKind::Transaction(transaction::Error::NotAllowed), _)) => {
					not_allowed_transactions.insert(hash);
					debug!(target: "miner", "Skipping non-allowed transaction for sender {:?}", hash);
				},
				Err(e) => {
					debug!(target: "txqueue", "[{:?}] Marking as invalid: {:?}.", hash, e);
					debug!(
						target: "miner", "Error adding transaction to block: number={}. transaction_hash={:?}, Error: {:?}", block_number, hash, e
					);
					invalid_transactions.insert(hash);
				},
				// imported ok
				_ => tx_count += 1,
			}
		}
		let elapsed = block_start.elapsed();
		debug!(target: "miner", "Pushed {} transactions in {} ms", tx_count, took_ms(&elapsed));

		let block = open_block.close();

		{
			self.transaction_queue.remove(invalid_transactions.iter(), true);
			self.transaction_queue.remove(not_allowed_transactions.iter(), false);
			self.transaction_queue.penalize(senders_to_penalize.iter());
		}

		(block, original_work_hash)
	}

	/// Returns `true` if we should create pending block even if some other conditions are not met.
	///
	/// In general we always seal iff:
	/// 1. --force-sealing CLI parameter is provided
	/// 2. There are listeners awaiting new work packages (e.g. remote work notifications or stratum).
	fn forced_sealing(&self) -> bool {
		self.options.force_sealing || !self.listeners.read().is_empty()
	}

	/// Check is reseal is allowed and necessary.
	fn requires_reseal(&self, best_block: BlockNumber) -> bool {
		let mut sealing = self.sealing.lock();
		if !sealing.enabled {
			trace!(target: "miner", "requires_reseal: sealing is disabled");
			return false
		}

		if !sealing.reseal_allowed() {
			trace!(target: "miner", "requires_reseal: reseal too early");
			return false
		}

		trace!(target: "miner", "requires_reseal: sealing enabled");

		// Disable sealing if there were no requests for SEALING_TIMEOUT_IN_BLOCKS
		let had_requests = best_block > sealing.last_request
			&& best_block - sealing.last_request <= SEALING_TIMEOUT_IN_BLOCKS;

		// keep sealing enabled if any of the conditions is met
		let sealing_enabled = self.forced_sealing()
			|| self.transaction_queue.has_local_pending_transactions()
			|| self.engine.seals_internally() == Some(true)
			|| had_requests;

		let should_disable_sealing = !sealing_enabled;

		trace!(target: "miner", "requires_reseal: should_disable_sealing={}; forced={:?}, has_local={:?}, internal={:?}, had_requests={:?}",
			should_disable_sealing,
			self.forced_sealing(),
			self.transaction_queue.has_local_pending_transactions(),
			self.engine.seals_internally(),
			had_requests,
		);

		if should_disable_sealing {
			trace!(target: "miner", "Miner sleeping (current {}, last {})", best_block, sealing.last_request);
			sealing.enabled = false;
			sealing.queue.reset();
			false
		} else {
			// sealing enabled and we don't want to sleep.
			sealing.next_allowed_reseal = Instant::now() + self.options.reseal_min_period;
			true
		}
	}

	/// Attempts to perform internal sealing (one that does not require work) and handles the result depending on the type of Seal.
	fn seal_and_import_block_internally<C>(&self, chain: &C, block: ClosedBlock) -> bool
		where C: BlockChain + SealedBlockImporter,
	{
		{
			let sealing = self.sealing.lock();
			if block.transactions().is_empty()
				&& !self.forced_sealing()
				&& Instant::now() <= sealing.next_mandatory_reseal
			{
				return false
			}
		}

		trace!(target: "miner", "seal_block_internally: attempting internal seal.");

		let parent_header = match chain.block_header(BlockId::Hash(*block.header().parent_hash())) {
			Some(h) => {
				match h.decode() {
					Ok(decoded_hdr) => decoded_hdr,
					Err(_) => return false
				}
			}
			None => return false,
		};

		match self.engine.generate_seal(block.block(), &parent_header) {
			// Save proposal for later seal submission and broadcast it.
			Seal::Proposal(seal) => {
				trace!(target: "miner", "Received a Proposal seal.");
				{
					let mut sealing = self.sealing.lock();
					sealing.next_mandatory_reseal = Instant::now() + self.options.reseal_max_period;
					sealing.queue.push(block.clone());
					sealing.queue.use_last_ref();
				}

				block
					.lock()
					.seal(&*self.engine, seal)
					.map(|sealed| {
						chain.broadcast_proposal_block(sealed);
						true
					})
					.unwrap_or_else(|e| {
						warn!("ERROR: seal failed when given internally generated seal: {}", e);
						false
					})
			},
			// Directly import a regular sealed block.
			Seal::Regular(seal) => {
				trace!(target: "miner", "Received a Regular seal.");
				{
					let mut sealing = self.sealing.lock();
					sealing.next_mandatory_reseal = Instant::now() + self.options.reseal_max_period;
				}

				block
					.lock()
					.seal(&*self.engine, seal)
					.map(|sealed| {
						chain.import_sealed_block(sealed).is_ok()
					})
					.unwrap_or_else(|e| {
						warn!("ERROR: seal failed when given internally generated seal: {}", e);
						false
					})
			},
			Seal::None => false,
		}
	}

	/// Prepares work which has to be done to seal.
	fn prepare_work(&self, block: ClosedBlock, original_work_hash: Option<H256>) {
		let (work, is_new) = {
			let block_header = block.block().header().clone();
			let block_hash = block_header.hash();

			let mut sealing = self.sealing.lock();
			let last_work_hash = sealing.queue.peek_last_ref().map(|pb| pb.block().header().hash());

			trace!(
				target: "miner",
				"prepare_work: Checking whether we need to reseal: orig={:?} last={:?}, this={:?}",
				original_work_hash, last_work_hash, block_hash
			);

			let (work, is_new) = if last_work_hash.map_or(true, |h| h != block_hash) {
				trace!(
					target: "miner",
					"prepare_work: Pushing a new, refreshed or borrowed pending {}...",
					block_hash
				);
				let is_new = original_work_hash.map_or(true, |h| h != block_hash);

				sealing.queue.push(block);
				// If push notifications are enabled we assume all work items are used.
				if is_new && !self.listeners.read().is_empty() {
					sealing.queue.use_last_ref();
				}

				(Some((block_hash, *block_header.difficulty(), block_header.number())), is_new)
			} else {
				(None, false)
			};
			trace!(
				target: "miner",
				"prepare_work: leaving (last={:?})",
				sealing.queue.peek_last_ref().map(|b| b.block().header().hash())
			);
			(work, is_new)
		};
		if is_new {
			work.map(|(pow_hash, difficulty, number)| {
				for notifier in self.listeners.read().iter() {
					notifier.notify(pow_hash, difficulty, number)
				}
			});
		}
	}

	/// Returns true if we had to prepare new pending block.
	fn prepare_pending_block<C>(&self, client: &C) -> bool where
		C: BlockChain + CallContract + BlockProducer + SealedBlockImporter + Nonce + Sync,
	{
		trace!(target: "miner", "prepare_pending_block: entering");
		let prepare_new = {
			let mut sealing = self.sealing.lock();
			let have_work = sealing.queue.peek_last_ref().is_some();
			trace!(target: "miner", "prepare_pending_block: have_work={}", have_work);
			if !have_work {
				sealing.enabled = true;
				true
			} else {
				false
			}
		};

		if prepare_new {
			// --------------------------------------------------------------------------
			// | NOTE Code below requires sealing locks.                                |
			// | Make sure to release the locks before calling that method.             |
			// --------------------------------------------------------------------------
			let (block, original_work_hash) = self.prepare_block(client);
			self.prepare_work(block, original_work_hash);
		}

		let best_number = client.chain_info().best_block_number;
		let mut sealing = self.sealing.lock();
		if sealing.last_request != best_number {
			trace!(
				target: "miner",
				"prepare_pending_block: Miner received request (was {}, now {}) - waking up.",
				sealing.last_request, best_number
			);
			sealing.last_request = best_number;
		}

		// Return if we restarted
		prepare_new
	}
}

const SEALING_TIMEOUT_IN_BLOCKS : u64 = 5;

impl miner::MinerService for Miner {
	type State = State<::state_db::StateDB>;

	fn authoring_params(&self) -> AuthoringParams {
		self.params.read().clone()
	}

	fn set_gas_range_target(&self, gas_range_target: (U256, U256)) {
		self.params.write().gas_range_target = gas_range_target;
	}

	fn set_extra_data(&self, extra_data: Bytes) {
		self.params.write().extra_data = extra_data;
	}

	fn set_author(&self, address: Address, password: Option<String>) -> Result<(), AccountError> {
		self.params.write().author = address;

		if self.engine.seals_internally().is_some() && password.is_some() {
			if let Some(ref ap) = self.accounts {
				let password = password.unwrap_or_default();
				// Sign test message
				ap.sign(address.clone(), Some(password.clone()), Default::default())?;
				// Enable sealing
				self.sealing.lock().enabled = true;
				// --------------------------------------------------------------------------
				// | NOTE Code below may require author and sealing locks                   |
				// | (some `Engine`s call `EngineClient.update_sealing()`)                  |
				// | Make sure to release the locks before calling that method.             |
				// --------------------------------------------------------------------------
				self.engine.set_signer(ap.clone(), address, password);
				Ok(())
			} else {
				warn!(target: "miner", "No account provider");
				Err(AccountError::NotFound)
			}
		} else {
			Ok(())
		}
	}

	fn sensible_gas_price(&self) -> U256 {
		// 10% above our minimum.
		self.transaction_queue.current_worst_gas_price() * 110u32 / 100.into()
	}

	fn sensible_gas_limit(&self) -> U256 {
		self.params.read().gas_range_target.0 / 5.into()
	}

	fn import_external_transactions<C: miner::BlockChainClient>(
		&self,
		chain: &C,
		transactions: Vec<UnverifiedTransaction>
	) -> Vec<Result<(), transaction::Error>> {
		trace!(target: "external_tx", "Importing external transactions");
		let client = self.pool_client(chain);
		let results = self.transaction_queue.import(
			client,
			transactions.into_iter().map(pool::verifier::Transaction::Unverified).collect(),
		);

		if !results.is_empty() && self.options.reseal_on_external_tx &&	self.sealing.lock().reseal_allowed() {
			// --------------------------------------------------------------------------
			// | NOTE Code below requires sealing locks.                                |
			// | Make sure to release the locks before calling that method.             |
			// --------------------------------------------------------------------------
			self.update_sealing(chain);
		}

		results
	}

	fn import_own_transaction<C: miner::BlockChainClient>(
		&self,
		chain: &C,
		pending: PendingTransaction,
	) -> Result<(), transaction::Error> {

		trace!(target: "own_tx", "Importing transaction: {:?}", pending);

		let client = self.pool_client(chain);
		let imported = self.transaction_queue.import(
			client,
			vec![pool::verifier::Transaction::Local(pending)]
		).pop().expect("one result returned per added transaction; one added => one result; qed");

		// --------------------------------------------------------------------------
		// | NOTE Code below requires sealing locks.                                |
		// | Make sure to release the locks before calling that method.             |
		// --------------------------------------------------------------------------
		if imported.is_ok() && self.options.reseal_on_own_tx && self.sealing.lock().reseal_allowed() {
			// Make sure to do it after transaction is imported and lock is droped.
			// We need to create pending block and enable sealing.
			if self.engine.seals_internally().unwrap_or(false) || !self.prepare_pending_block(chain) {
				// If new block has not been prepared (means we already had one)
				// or Engine might be able to seal internally,
				// we need to update sealing.
				self.update_sealing(chain);
			}
		}

		imported
	}

	fn local_transactions(&self) -> BTreeMap<H256, pool::local_transactions::Status> {
		self.transaction_queue.local_transactions()
	}

	fn queued_transactions(&self) -> Vec<Arc<VerifiedTransaction>> {
		self.transaction_queue.all_transactions()
	}

	fn ready_transactions<C>(&self, chain: &C) -> Vec<Arc<VerifiedTransaction>> where
		C: ChainInfo + Nonce + Sync,
	{
		let chain_info = chain.chain_info();

		let from_queue = || {
			self.transaction_queue.pending(
				CachedNonceClient::new(chain, &self.nonce_cache),
				chain_info.best_block_number,
				chain_info.best_block_timestamp,
				// We propagate transactions over the nonce cap.
				// The mechanism is only to limit number of transactions in pending block
				// those transactions are valid and will just be ready to be included in next block.
				None,
			)
		};

		let from_pending = || {
			self.map_existing_pending_block(|sealing| {
				sealing.transactions()
					.iter()
					.map(|signed| pool::VerifiedTransaction::from_pending_block_transaction(signed.clone()))
					.map(Arc::new)
					.collect()
			}, chain_info.best_block_number)
		};

		match self.options.pending_set {
			PendingSet::AlwaysQueue => {
				from_queue()
			},
			PendingSet::AlwaysSealing => {
				from_pending().unwrap_or_default()
			},
			PendingSet::SealingOrElseQueue => {
				from_pending().unwrap_or_else(from_queue)
			},
		}
	}

	fn next_nonce<C>(&self, chain: &C, address: &Address) -> U256 where
		C: Nonce + Sync,
	{
		self.transaction_queue.next_nonce(CachedNonceClient::new(chain, &self.nonce_cache), address)
			.unwrap_or_else(|| chain.latest_nonce(address))
	}

	fn transaction(&self, hash: &H256) -> Option<Arc<VerifiedTransaction>> {
		self.transaction_queue.find(hash)
	}

	fn remove_transaction(&self, hash: &H256) -> Option<Arc<VerifiedTransaction>> {
		self.transaction_queue.remove(::std::iter::once(hash), false)
			.pop()
			.expect("remove() returns one result per hash; one hash passed; qed")
	}

	fn queue_status(&self) -> QueueStatus {
		self.transaction_queue.status()
	}

	fn pending_receipt(&self, best_block: BlockNumber, hash: &H256) -> Option<RichReceipt> {
		self.map_existing_pending_block(|pending| {
			let txs = pending.transactions();
			txs.iter()
				.map(|t| t.hash())
				.position(|t| t == *hash)
				.map(|index| {
					let receipts = pending.receipts();
					let prev_gas = if index == 0 { Default::default() } else { receipts[index - 1].gas_used };
					let tx = &txs[index];
					let receipt = &receipts[index];
					RichReceipt {
						transaction_hash: hash.clone(),
						transaction_index: index,
						cumulative_gas_used: receipt.gas_used,
						gas_used: receipt.gas_used - prev_gas,
						contract_address: match tx.action {
							Action::Call(_) => None,
							Action::Create => {
								let sender = tx.sender();
								Some(contract_address(self.engine.create_address_scheme(pending.header().number()), &sender, &tx.nonce, &tx.data).0)
							}
						},
						logs: receipt.logs.clone(),
						log_bloom: receipt.log_bloom,
						outcome: receipt.outcome.clone(),
					}
				})
		}, best_block).and_then(|x| x)
	}

	fn pending_receipts(&self, best_block: BlockNumber) -> Option<BTreeMap<H256, Receipt>> {
		self.map_existing_pending_block(|pending| {
			let hashes = pending.transactions().iter().map(|t| t.hash());
			let receipts = pending.receipts().iter().cloned();

			hashes.zip(receipts).collect()
		}, best_block)
	}

	/// Update sealing if required.
	/// Prepare the block and work if the Engine does not seal internally.
	fn update_sealing<C>(&self, chain: &C) where
		C: BlockChain + CallContract + BlockProducer + SealedBlockImporter + Nonce + Sync,
	{
		trace!(target: "miner", "update_sealing");

		// Do nothing if reseal is not required,
		// but note that `requires_reseal` updates internal state.
		if !self.requires_reseal(chain.chain_info().best_block_number) {
			return;
		}

		// --------------------------------------------------------------------------
		// | NOTE Code below requires sealing locks.                                |
		// | Make sure to release the locks before calling that method.             |
		// --------------------------------------------------------------------------
		trace!(target: "miner", "update_sealing: preparing a block");
		let (block, original_work_hash) = self.prepare_block(chain);

		// refuse to seal the first block of the chain if it contains hard forks
		// which should be on by default.
		if block.block().header().number() == 1 && self.engine.params().contains_bugfix_hard_fork() {
			warn!("Your chain specification contains one or more hard forks which are required to be \
				on by default. Please remove these forks and start your chain again.");
			return;
		}

		match self.engine.seals_internally() {
			Some(true) => {
				trace!(target: "miner", "update_sealing: engine indicates internal sealing");
				if self.seal_and_import_block_internally(chain, block) {
					trace!(target: "miner", "update_sealing: imported internally sealed block");
				}
			},
			Some(false) => {
				trace!(target: "miner", "update_sealing: engine is not keen to seal internally right now");
				// anyway, save the block for later use
				self.sealing.lock().queue.push(block);
			},
			None => {
				trace!(target: "miner", "update_sealing: engine does not seal internally, preparing work");
				self.prepare_work(block, original_work_hash)
			},
		}
	}

	fn is_currently_sealing(&self) -> bool {
		self.sealing.lock().queue.is_in_use()
	}

	fn work_package<C>(&self, chain: &C) -> Option<(H256, BlockNumber, u64, U256)> where
		C: BlockChain + CallContract + BlockProducer + SealedBlockImporter + Nonce + Sync,
	{
		if self.engine.seals_internally().is_some() {
			return None;
		}

		self.prepare_pending_block(chain);

		self.sealing.lock().queue.use_last_ref().map(|b| {
			let header = b.header();
			(header.hash(), header.number(), header.timestamp(), *header.difficulty())
		})
	}

	// Note used for external submission (PoW) and internally by sealing engines.
	fn submit_seal(&self, block_hash: H256, seal: Vec<Bytes>) -> Result<SealedBlock, Error> {
		let result =
			if let Some(b) = self.sealing.lock().queue.get_used_if(
				if self.options.enable_resubmission {
					GetAction::Clone
				} else {
					GetAction::Take
				},
				|b| &b.hash() == &block_hash
			) {
				trace!(target: "miner", "Submitted block {}={}={} with seal {:?}", block_hash, b.hash(), b.header().bare_hash(), seal);
				b.lock().try_seal(&*self.engine, seal).or_else(|(e, _)| {
					warn!(target: "miner", "Mined solution rejected: {}", e);
					Err(ErrorKind::PowInvalid.into())
				})
			} else {
				warn!(target: "miner", "Submitted solution rejected: Block unknown or out of date.");
				Err(ErrorKind::PowHashInvalid.into())
			};

		result.and_then(|sealed| {
			let n = sealed.header().number();
			let h = sealed.header().hash();
			info!(target: "miner", "Submitted block imported OK. #{}: {}", Colour::White.bold().paint(format!("{}", n)), Colour::White.bold().paint(format!("{:x}", h)));
			Ok(sealed)
		})
	}

	fn chain_new_blocks<C>(&self, chain: &C, imported: &[H256], _invalid: &[H256], enacted: &[H256], retracted: &[H256], is_internal_import: bool)
		where C: miner::BlockChainClient,
	{
		trace!(target: "miner", "chain_new_blocks");

		// 1. We ignore blocks that were `imported` unless resealing on new uncles is enabled.
		// 2. We ignore blocks that are `invalid` because it doesn't have any meaning in terms of the transactions that
		//    are in those blocks

		// Clear nonce cache
		self.nonce_cache.write().clear();

		// First update gas limit in transaction queue and minimal gas price.
		let gas_limit = *chain.best_block_header().gas_limit();
		self.update_transaction_queue_limits(gas_limit);

		// Then import all transactions...
		let client = self.pool_client(chain);
		{
			retracted
				.par_iter()
				.for_each(|hash| {
					let block = chain.block(BlockId::Hash(*hash))
						.expect("Client is sending message after commit to db and inserting to chain; the block is available; qed");
					let txs = block.transactions()
						.into_iter()
						.map(pool::verifier::Transaction::Retracted)
						.collect();
					let _ = self.transaction_queue.import(
						client.clone(),
						txs,
					);
				});
		}

		// ...and at the end remove the old ones
		self.transaction_queue.cull(client);

		if enacted.len() > 0 || (imported.len() > 0 && self.options.reseal_on_uncle) {
			// Reset `next_allowed_reseal` in case a block is imported.
			// Even if min_period is high, we will always attempt to create
			// new pending block.
			self.sealing.lock().next_allowed_reseal = Instant::now();

			if !is_internal_import {
				// --------------------------------------------------------------------------
				// | NOTE Code below requires sealing locks.                                |
				// | Make sure to release the locks before calling that method.             |
				// --------------------------------------------------------------------------
				self.update_sealing(chain);
			}
		}
	}

	fn pending_state(&self, latest_block_number: BlockNumber) -> Option<Self::State> {
		self.map_existing_pending_block(|b| b.state().clone(), latest_block_number)
	}

	fn pending_block_header(&self, latest_block_number: BlockNumber) -> Option<Header> {
		self.map_existing_pending_block(|b| b.header().clone(), latest_block_number)
	}

	fn pending_block(&self, latest_block_number: BlockNumber) -> Option<Block> {
		self.map_existing_pending_block(|b| b.to_base(), latest_block_number)
	}

	fn pending_transactions(&self, latest_block_number: BlockNumber) -> Option<Vec<SignedTransaction>> {
		self.map_existing_pending_block(|b| b.transactions().into_iter().cloned().collect(), latest_block_number)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ethkey::{Generator, Random};
	use hash::keccak;
	use header::BlockNumber;
	use rustc_hex::FromHex;

	use client::{TestBlockChainClient, EachBlockWith, ChainInfo, ImportSealedBlock};
	use miner::MinerService;
	use test_helpers::{generate_dummy_client, generate_dummy_client_with_spec_and_accounts};
	use transaction::{Transaction};

	#[test]
	fn should_prepare_block_to_seal() {
		// given
		let client = TestBlockChainClient::default();
		let miner = Miner::new_for_tests(&Spec::new_test(), None);

		// when
		let sealing_work = miner.work_package(&client);
		assert!(sealing_work.is_some(), "Expected closed block");
	}

	#[test]
	fn should_still_work_after_a_couple_of_blocks() {
		// given
		let client = TestBlockChainClient::default();
		let miner = Miner::new_for_tests(&Spec::new_test(), None);

		let res = miner.work_package(&client);
		let hash = res.unwrap().0;
		let block = miner.submit_seal(hash, vec![]).unwrap();
		client.import_sealed_block(block).unwrap();

		// two more blocks mined, work requested.
		client.add_blocks(1, EachBlockWith::Uncle);
		miner.work_package(&client);

		client.add_blocks(1, EachBlockWith::Uncle);
		miner.work_package(&client);

		// solution to original work submitted.
		assert!(miner.submit_seal(hash, vec![]).is_ok());
	}

	fn miner() -> Miner {
		Miner::new(
			MinerOptions {
				force_sealing: false,
				reseal_on_external_tx: false,
				reseal_on_own_tx: true,
				reseal_on_uncle: false,
				reseal_min_period: Duration::from_secs(5),
				reseal_max_period: Duration::from_secs(120),
				pending_set: PendingSet::AlwaysSealing,
				work_queue_size: 5,
				enable_resubmission: true,
				infinite_pending_block: false,
				tx_queue_penalization: Penalization::Disabled,
				tx_queue_strategy: PrioritizationStrategy::GasPriceOnly,
				refuse_service_transactions: false,
				pool_limits: Default::default(),
				pool_verification_options: pool::verifier::Options {
					minimal_gas_price: 0.into(),
					block_gas_limit: U256::max_value(),
					tx_gas_limit: U256::max_value(),
				},
			},
			GasPricer::new_fixed(0u64.into()),
			&Spec::new_test(),
			None, // accounts provider
		)
	}

	fn transaction() -> SignedTransaction {
		transaction_with_chain_id(2)
	}

	fn transaction_with_chain_id(chain_id: u64) -> SignedTransaction {
		let keypair = Random.generate().unwrap();
		Transaction {
			action: Action::Create,
			value: U256::zero(),
			data: "3331600055".from_hex().unwrap(),
			gas: U256::from(100_000),
			gas_price: U256::zero(),
			nonce: U256::zero(),
		}.sign(keypair.secret(), Some(chain_id))
	}

	#[test]
	fn should_make_pending_block_when_importing_own_transaction() {
		// given
		let client = TestBlockChainClient::default();
		let miner = miner();
		let transaction = transaction();
		let best_block = 0;
		// when
		let res = miner.import_own_transaction(&client, PendingTransaction::new(transaction, None));

		// then
		assert_eq!(res.unwrap(), ());
		assert_eq!(miner.pending_transactions(best_block).unwrap().len(), 1);
		assert_eq!(miner.pending_receipts(best_block).unwrap().len(), 1);
		assert_eq!(miner.ready_transactions(&client).len(), 1);
		// This method will let us know if pending block was created (before calling that method)
		assert!(!miner.prepare_pending_block(&client));
	}

	#[test]
	fn should_not_use_pending_block_if_best_block_is_higher() {
		// given
		let client = TestBlockChainClient::default();
		let miner = miner();
		let transaction = transaction();
		let best_block = 10;
		// when
		let res = miner.import_own_transaction(&client, PendingTransaction::new(transaction, None));

		// then
		assert_eq!(res.unwrap(), ());
		assert_eq!(miner.pending_transactions(best_block), None);
		assert_eq!(miner.pending_receipts(best_block), None);
		assert_eq!(miner.ready_transactions(&client).len(), 1);
	}

	#[test]
	fn should_import_external_transaction() {
		// given
		let client = TestBlockChainClient::default();
		let miner = miner();
		let transaction = transaction().into();
		let best_block = 0;
		// when
		let res = miner.import_external_transactions(&client, vec![transaction]).pop().unwrap();

		// then
		assert_eq!(res.unwrap(), ());
		// By default we don't reseal on external transactions
		assert_eq!(miner.pending_transactions(best_block), None);
		assert_eq!(miner.pending_receipts(best_block), None);
		// By default we use PendingSet::AlwaysSealing, so no transactions yet.
		assert_eq!(miner.ready_transactions(&client).len(), 0);
		// This method will let us know if pending block was created (before calling that method)
		assert!(miner.prepare_pending_block(&client));
		// After pending block is created we should see a transaction.
		assert_eq!(miner.ready_transactions(&client).len(), 1);
	}

	#[test]
	fn should_not_seal_unless_enabled() {
		let miner = miner();
		let client = TestBlockChainClient::default();
		// By default resealing is not required.
		assert!(!miner.requires_reseal(1u8.into()));

		miner.import_external_transactions(&client, vec![transaction().into()]).pop().unwrap().unwrap();
		assert!(miner.prepare_pending_block(&client));
		// Unless asked to prepare work.
		assert!(miner.requires_reseal(1u8.into()));
	}

	#[test]
	fn internal_seals_without_work() {
		let spec = Spec::new_instant();
		let miner = Miner::new_for_tests(&spec, None);

		let client = generate_dummy_client(2);

		let import = miner.import_external_transactions(&*client, vec![transaction_with_chain_id(spec.chain_id()).into()]).pop().unwrap();
		assert_eq!(import.unwrap(), ());

		miner.update_sealing(&*client);
		client.flush_queue();
		assert!(miner.pending_block(0).is_none());
		assert_eq!(client.chain_info().best_block_number, 3 as BlockNumber);

		assert!(miner.import_own_transaction(&*client, PendingTransaction::new(transaction_with_chain_id(spec.chain_id()).into(), None)).is_ok());

		miner.update_sealing(&*client);
		client.flush_queue();
		assert!(miner.pending_block(0).is_none());
		assert_eq!(client.chain_info().best_block_number, 4 as BlockNumber);
	}

	#[test]
	fn should_fail_setting_engine_signer_without_account_provider() {
		let spec = Spec::new_instant;
		let tap = Arc::new(AccountProvider::transient_provider());
		let addr = tap.insert_account(keccak("1").into(), "").unwrap();
		let client = generate_dummy_client_with_spec_and_accounts(spec, None);
		assert!(match client.miner().set_author(addr, Some("".into())) { Err(AccountError::NotFound) => true, _ => false });
	}
}
