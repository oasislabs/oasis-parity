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
use std::{
	cell::{RefCell, UnsafeCell},
	sync::Arc,
};

use bcfs::BCFS;
use blockchain_traits::{KVStore, KVStoreMut, PendingTransaction, TransactionOutcome};
use common_types::{u128_from_u256, u256_from_u128};
use ethereum_types::{Address, H256, U256};
use vm::{self, CallType, MessageCallResult, ReturnData};
use wasmi::{self, Error as InterpreterError, MemoryRef, Trap, TrapKind};

pub struct RuntimeContext {
	pub address: Address,
	pub sender: Address,
	pub origin: Address,
	pub code_address: Address,
	pub value: U256,
	pub value_str: String,
	pub aad_str: String,
}

pub const RNG_HASH_BYTES: usize = 256 / 8; // sha256

pub struct Runtime<'a> {
	pub gas_counter: u64,
	pub gas_limit: u64,
	pub ext: &'a mut dyn vm::Ext,
	pub context: RuntimeContext,
	pub memory: MemoryRef,
	pub args: Vec<u8>,
	pub output: Vec<u8>,
	pub err_output: Vec<u8>,
	// unsafety is needed because runtime contains BCFS but is used by bcfs as PendingTransaction
	pub bcfs: UnsafeCell<BCFS>,
	pub should_revert: bool,
	pub bytes_cache: RefCell<Vec<Arc<Vec<u8>>>>,
	pub rng: hmac_drbg::HmacDRBG<sha2::Sha256>,
}

pub struct Receipt {
	caller: oasis_types::Address,
	callee: oasis_types::Address,
	gas_used: u64,
	outcome: TransactionOutcome,
	output: ReturnData,
}

impl blockchain_traits::Receipt for Receipt {
	fn caller(&self) -> &oasis_types::Address {
		&self.caller
	}

	fn callee(&self) -> &oasis_types::Address {
		&self.callee
	}

	fn gas_used(&self) -> u64 {
		self.gas_used
	}

	fn events(&self) -> Vec<&oasis_types::Event> {
		unimplemented!()
	}

	/// Returns the outcome of this transaction.
	fn outcome(&self) -> TransactionOutcome {
		self.outcome
	}

	/// Returns the output of the transaction.
	fn output(&self) -> &[u8] {
		&self.output
	}
}

impl<'a> PendingTransaction for Runtime<'a> {
	fn address(&self) -> &oasis_types::Address {
		eaddr2maddr(&self.context.address)
	}

	fn sender(&self) -> &oasis_types::Address {
		eaddr2maddr(&self.context.sender)
	}

	fn value(&self) -> u128 {
		u128_from_u256(self.context.value)
	}

	fn input(&self) -> &[u8] {
		&self.args
	}

	/// Executes a balance-transferring RPC to `callee` with provided input and value.
	/// The new transaction will inherit the gas parameters and gas payer of the top level
	/// transaction. The current account will be set as the sender.
	fn transact(
		&mut self,
		callee: oasis_types::Address,
		value: u128,
		input: &[u8],
	) -> Box<dyn blockchain_traits::Receipt> {
		trace!(target: "wasm", "runtime: CALL(callee: {:?}, value: {:?}), input {:?}", callee, value, input);

		let mut receipt = Box::new(Receipt {
			caller: *eaddr2maddr(&self.context.address),
			callee,
			gas_used: 0,
			outcome: TransactionOutcome::Fatal,
			output: ReturnData::empty(),
		});

		if let Err(err) = self.adjusted_charge(|schedule| Some(schedule.call_gas as u64)) {
			trace!("CALL failed adjusted charge {:?}", err);
		}

		let pre_gas_left = match self.gas_left() {
			Ok(gas_left) => gas_left,
			Err(_) => {
				receipt.outcome = TransactionOutcome::InsufficientGas;
				return receipt;
			}
		};

		let callee = maddr2eaddr(&callee);
		let call_result = self.ext.call(
			&pre_gas_left.into(),
			&self.context.address, /* sender */
			callee,                /* receiver */
			if value > 0 {
				Some(u256_from_u128(value))
			} else {
				None
			},
			input,
			callee, /* code addr */
			&mut [],
			CallType::Call,
		);

		match call_result {
			MessageCallResult::Success(..) => receipt.outcome = TransactionOutcome::Success,
			MessageCallResult::Reverted(..) => receipt.outcome = TransactionOutcome::Aborted,
			MessageCallResult::Failed => receipt.outcome = TransactionOutcome::Fatal,
		}

		match call_result {
			MessageCallResult::Success(post_gas_left, return_data)
			| MessageCallResult::Reverted(post_gas_left, return_data) => {
				receipt.gas_used = pre_gas_left - post_gas_left.low_u64();
				// ^ by definition pre_gas_left > post_gas_left so this cannot overflow
				if !self.charge_gas(receipt.gas_used) {
					// ^ cost for xcc is not be "adjusted" because functions called
					// during its scope are already individually adjusted.
					receipt.outcome = TransactionOutcome::InsufficientGas;
					receipt.gas_used = self.gas_limit;
					return receipt;
				}
				receipt.output = return_data;
			}
			MessageCallResult::Failed => {
				receipt.gas_used = self.gas_limit;
			}
		}
		return receipt;
	}

	/// Returns data to the calling transaction.
	fn ret(&mut self, data: &[u8]) {
		self.output.clear();
		self.output.extend_from_slice(data);
	}

	/// Returns error data to the calling context.
	fn err(&mut self, data: &[u8]) {
		self.err_output.clear();
		self.err_output.extend_from_slice(data);
	}

	/// Publishes a broadcast message in this block.
	fn emit(&mut self, topics: &[&[u8]], data: &[u8]) {
		const H256_BYTES: usize = 256 / 8;
		let mut htopics = Vec::with_capacity(std::cmp::min(topics.len(), 4));
		for topic in topics {
			let nbytes = std::cmp::min(topic.len(), H256_BYTES);
			let mut htopic = [0u8; H256_BYTES];
			htopic[..nbytes].copy_from_slice(&topic[..nbytes]);
			htopics.push(H256::from(htopic));
		}
		self.ext.log(htopics, data).ok();
	}

	/// Returns the state of the current account.
	fn state(&self) -> &dyn KVStore {
		self.ext.as_kvstore()
	}

	/// Returns the mutable state of the current account.
	fn state_mut(&mut self) -> &mut dyn KVStoreMut {
		self.ext.as_kvstore_mut()
	}

	/// Returns the bytecode stored at `addr` or `None` if the account does not exist.
	fn code_at(&self, addr: &oasis_types::Address) -> Option<&[u8]> {
		match self.ext.extcode(maddr2eaddr(addr)) {
			Ok(code_bytes) => {
				let bytes_ptr = &*code_bytes as *const Vec<u8>;
				let mut bytes_cache = self.bytes_cache.borrow_mut();
				bytes_cache.push(code_bytes); // keep the Arc alive
				Some(unsafe { &*bytes_ptr }.as_slice()) // heap-allocated bytes won't move
			}
			Err(_) => None,
		}
	}

	/// Returns the metadata of the account stored at `addr`, or
	/// `None` if the account does not exist.
	fn account_meta_at(&self, addr: &oasis_types::Address) -> Option<oasis_types::AccountMeta> {
		Some(oasis_types::AccountMeta {
			balance: match self.ext.balance(maddr2eaddr(addr)) {
				Ok(bal) if bal.bits() <= 128 => u128_from_u256(bal),
				_ => return None,
			},
			expiry: self
				.ext
				.storage_expiry(maddr2eaddr(addr))
				.ok()
				.map(std::time::Duration::from_secs),
		})
	}
}

pub fn maddr2eaddr(addr: &oasis_types::Address) -> &ethereum_types::Address {
	// this is safe because both `Address` types are newtypes containing [u8; 32]
	unsafe { std::mem::transmute(addr) }
}

pub fn eaddr2maddr(addr: &ethereum_types::Address) -> &oasis_types::Address {
	// this is safe because both `Address` types are newtypes containing [u8; 32]
	unsafe { std::mem::transmute(addr) }
}

/// User trap in native code
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
	/// Storage read error
	StorageReadError,
	/// Storage update error
	StorageUpdateError,
	/// Memory access violation
	MemoryAccessViolation,
	/// Native code resulted in suicide
	Suicide,
	/// Native code requested execution to finish
	Return,
	/// Suicide was requested but coudn't complete
	SuicideAbort,
	/// Invalid gas state inside interpreter
	InvalidGasState,
	/// Query of the balance resulted in an error
	BalanceQueryError,
	/// Failed allocation
	AllocationFailed,
	/// Gas limit reached
	GasLimit,
	/// Unknown runtime function
	Unknown,
	/// Passed string had invalid utf-8 encoding
	BadUtf8,
	/// Log event error
	Log,
	/// Other error in native code
	Other,
	/// Syscall signature mismatch
	InvalidSyscall,
	/// Unreachable instruction encountered
	Unreachable,
	/// Invalid virtual call
	InvalidVirtualCall,
	/// Division by zero
	DivisionByZero,
	/// Invalid conversion to integer
	InvalidConversionToInt,
	/// Stack overflow
	StackOverflow,
	/// Panic with message
	Panic(String),
}

impl wasmi::HostError for Error {}

impl From<Trap> for Error {
	fn from(trap: Trap) -> Self {
		match *trap.kind() {
			TrapKind::Unreachable => Error::Unreachable,
			TrapKind::MemoryAccessOutOfBounds => Error::MemoryAccessViolation,
			TrapKind::TableAccessOutOfBounds | TrapKind::ElemUninitialized => {
				Error::InvalidVirtualCall
			}
			TrapKind::DivisionByZero => Error::DivisionByZero,
			TrapKind::InvalidConversionToInt => Error::InvalidConversionToInt,
			TrapKind::UnexpectedSignature => Error::InvalidVirtualCall,
			TrapKind::StackOverflow => Error::StackOverflow,
			TrapKind::Host(_) => Error::Other,
		}
	}
}

impl From<InterpreterError> for Error {
	fn from(err: InterpreterError) -> Self {
		match err {
			InterpreterError::Value(_) => Error::InvalidSyscall,
			InterpreterError::Memory(_) => Error::MemoryAccessViolation,
			_ => Error::Other,
		}
	}
}

impl ::std::fmt::Display for Error {
	fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::result::Result<(), ::std::fmt::Error> {
		match *self {
			Error::StorageReadError => write!(f, "Storage read error"),
			Error::StorageUpdateError => write!(f, "Storage update error"),
			Error::MemoryAccessViolation => write!(f, "Memory access violation"),
			Error::SuicideAbort => write!(f, "Attempt to suicide resulted in an error"),
			Error::InvalidGasState => write!(f, "Invalid gas state"),
			Error::BalanceQueryError => write!(f, "Balance query resulted in an error"),
			Error::Suicide => write!(f, "Suicide result"),
			Error::Return => write!(f, "Return result"),
			Error::Unknown => write!(f, "Unknown runtime function invoked"),
			Error::AllocationFailed => write!(f, "Memory allocation failed (OOM)"),
			Error::BadUtf8 => write!(f, "String encoding is bad utf-8 sequence"),
			Error::GasLimit => write!(f, "Invocation resulted in gas limit violated"),
			Error::Log => write!(f, "Error occured while logging an event"),
			Error::InvalidSyscall => write!(f, "Invalid syscall signature encountered at runtime"),
			Error::Other => write!(f, "Other unspecified error"),
			Error::Unreachable => write!(f, "Unreachable instruction encountered"),
			Error::InvalidVirtualCall => write!(f, "Invalid virtual call"),
			Error::DivisionByZero => write!(f, "Division by zero"),
			Error::StackOverflow => write!(f, "Stack overflow"),
			Error::InvalidConversionToInt => write!(f, "Invalid conversion to integer"),
			Error::Panic(ref msg) => write!(f, "Panic: {}", msg),
		}
	}
}

pub type Result<T> = ::std::result::Result<T, Error>;

impl<'a> Runtime<'a> {
	/// New runtime for wasm contract with specified params
	pub fn with_params(
		ext: &mut dyn vm::Ext,
		memory: MemoryRef,
		gas_limit: u64,
		args: Vec<u8>,
		context: RuntimeContext,
	) -> Runtime {
		let env_info = ext.env_info();
		let entropy = env_info.last_hashes.first().unwrap();
		let nonce = <[u8; 32]>::from(ext.origin_nonce())
			.iter()
			.chain(ext.depth().to_le_bytes().iter())
			.copied()
			.collect::<Vec<u8>>();
		//^ origin nonce will not be unique for a sub-call, so we swizzle in the current depth
		let personalization_string = env_info
			.timestamp
			.to_le_bytes()
			.iter()
			.chain(<[u8; 20]>::from(context.sender).iter())
			.chain(<[u8; 20]>::from(context.address).iter())
			.copied()
			.collect::<Vec<u8>>();
		// per https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf
		let rng = hmac_drbg::HmacDRBG::new(entropy, &nonce, &personalization_string);

		Runtime {
			bcfs: UnsafeCell::new(BCFS::new(*eaddr2maddr(&context.address), "oasis")),
			gas_counter: 0,
			gas_limit,
			memory,
			ext,
			context,
			args,
			rng,
			output: Vec::new(),
			err_output: Vec::new(),
			should_revert: false,
			bytes_cache: RefCell::new(Vec::new()),
		}
	}

	/// Charge specified amount of gas
	///
	/// Returns false if gas limit exceeded and true if not.
	/// Intuition about the return value sense is to aswer the question 'are we allowed to continue?'
	pub fn charge_gas(&mut self, amount: u64) -> bool {
		let prev = self.gas_counter;
		match prev.checked_add(amount) {
			// gas charge overflow protection
			None => false,
			Some(val) if val > self.gas_limit => false,
			Some(_) => {
				self.gas_counter = prev + amount;
				true
			}
		}
	}

	/// Charge gas provided by the closure
	///
	/// Closure also can return overflowing flag as None in gas cost.
	pub fn charge<F>(&mut self, f: F) -> Result<()>
	where
		F: FnOnce(&vm::Schedule) -> Option<u64>,
	{
		let amount = match f(self.ext.schedule()) {
			Some(amount) => amount,
			None => {
				return Err(Error::GasLimit.into());
			}
		};

		if !self.charge_gas(amount as u64) {
			Err(Error::GasLimit.into())
		} else {
			Ok(())
		}
	}

	/// Same as overflow_charge, but with amount adjusted by wasm opcodes coeff
	pub fn adjusted_charge<F>(&mut self, f: F) -> Result<()>
	where
		F: FnOnce(&vm::Schedule) -> Option<u64>,
	{
		self.charge(|schedule| {
			f(schedule)
				.and_then(|x| x.checked_mul(schedule.wasm().opcodes_div as u64))
				.map(|x| x / schedule.wasm().opcodes_mul as u64)
		})
	}

	/// Gas charge prorated based on time until expiry and the number of bytes we're storing.
	pub fn storage_bytes_charge(&mut self, bytes_len: u64, reset: bool) -> Result<()> {
		let duration_secs = self
			.ext
			.seconds_until_expiry()
			.map_err(|_| Error::StorageUpdateError)?;

		let gas = if !reset {
			self.ext
				.schedule()
				.prorated_sstore_set_gas(duration_secs, bytes_len)
		} else {
			self.ext
				.schedule()
				.prorated_sstore_reset_gas(duration_secs, bytes_len)
		};

		// Charge gas after checking for u64 overflow.
		if gas > U256::from(std::u64::MAX) {
			return Err(Error::GasLimit);
		} else {
			self.adjusted_charge(|_| Some(gas.as_u64()))?;
		}

		Ok(())
	}

	/// Return currently used schedule
	pub fn schedule(&self) -> &vm::Schedule {
		self.ext.schedule()
	}

	/// Destroy the runtime, returning currently recorded result of the execution
	pub fn into_result(mut self) -> std::result::Result<Vec<u8>, Vec<u8>> {
		let bcfs = unsafe { &mut *self.bcfs.get() };
		bcfs.flush(&mut self, 1u32.into()).ok(); // flush stdout
		bcfs.flush(&mut self, 2u32.into()).ok(); // flush stderr
		if self.should_revert {
			Err(self.err_output)
		} else {
			Ok(self.output)
		}
	}

	/// Query current gas left for execution
	pub fn gas_left(&self) -> Result<u64> {
		if self.gas_counter > self.gas_limit {
			return Err(Error::InvalidGasState);
		}
		Ok(self.gas_limit - self.gas_counter)
	}
}
