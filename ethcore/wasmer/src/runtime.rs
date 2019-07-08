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
	convert::TryFrom,
	convert::TryInto,
	sync::Arc,
};

use bcfs::BCFS;
use blockchain_traits::{KVStore, KVStoreMut, PendingTransaction, TransactionOutcome};
use ethereum_types::{Address, H256, U256};
use mantle_types::AccountMeta;
use vm::{self, CallType, MessageCallResult, ReturnData};

use wasi_types::*;
use wasmer_runtime::{memory::Memory, Ctx};
use wasmi::{self, Error as InterpreterError, Trap, TrapKind, P};

const ADDR_LEN_BYTES: usize = std::mem::size_of::<mantle_types::Address>();
const ADDR_CHARS: usize = ADDR_LEN_BYTES * 2; // two hex digits per byte

macro_rules! bcfs {
	( $self:ident . bcfs . $fn:ident ( $($args:expr),+ )  ) => {
		// Unsafety is required because BCFS is mutably borrowed with `self`
		// but also takes a `PendingTransaction` which also happens to be `self.
		// This is okay because BCFS doesn't modify itself through `PendingTransaction`.
		match unsafe { &mut *$self.bcfs.get() }.$fn($self, $( $args ),+ ) {
			Ok(result) => result,
			Err(errno) => return Ok(errno as u16)
		}
	}
}

pub struct RuntimeContext {
	pub address: Address,
	pub sender: Address,
	pub origin: Address,
	pub code_address: Address,
	pub value: U256,
	pub value_str: String,
}

pub struct Runtime<'a> {
	pub gas_counter: u64,
	pub gas_limit: u64,
	pub ext: &'a mut dyn vm::Ext,
	pub context: RuntimeContext,
	pub args: Vec<u8>,
	pub output: Vec<u8>,
	pub err_output: Vec<u8>,
	// unsafety is needed because runtime contains BCFS but is used by bcfs as PendingTransaction
	pub bcfs: UnsafeCell<BCFS<mantle_types::Address, AccountMeta>>,
	pub should_revert: bool,
	// Needed for wasmer since only generic CallError is returned on panic/exit
	pub should_persist: bool,
	pub bytes_cache: RefCell<Vec<Arc<Vec<u8>>>>,
}

pub struct Receipt {
	caller: mantle_types::Address,
	callee: mantle_types::Address,
	gas_used: u64,
	outcome: TransactionOutcome,
	output: ReturnData,
}

impl blockchain_traits::Receipt for Receipt {
	type Address = mantle_types::Address;

	fn caller(&self) -> &Self::Address {
		&self.caller
	}

	fn callee(&self) -> &Self::Address {
		&self.callee
	}

	fn gas_used(&self) -> u64 {
		self.gas_used
	}

	fn events(&self) -> Vec<&dyn blockchain_traits::Event<Address = Self::Address>> {
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
	type Address = mantle_types::Address;
	type AccountMeta = mantle_types::AccountMeta;

	fn address(&self) -> &Self::Address {
		eaddr2maddr(&self.context.address)
	}

	fn sender(&self) -> &Self::Address {
		eaddr2maddr(&self.context.sender)
	}

	fn value(&self) -> u64 {
		self.context.value.low_u64()
	}

	fn input(&self) -> &[u8] {
		&self.args
	}

	/// Executes a balance-transferring RPC to `callee` with provided input and value.
	/// The new transaction will inherit the gas parameters and gas payer of the top level
	/// transaction. The current account will be set as the sender.
	fn transact(
		&mut self,
		callee: Self::Address,
		value: u64,
		input: &[u8],
	) -> Box<dyn blockchain_traits::Receipt<Address = Self::Address>> {
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

		let gas_left = match self.gas_left() {
			Ok(gas_left) => gas_left,
			Err(_) => {
				receipt.outcome = TransactionOutcome::InsufficientGas;
				return receipt;
			}
		};

		let callee = maddr2eaddr(&callee);
		let call_result = self.ext.call(
			&gas_left.into(),
			&self.context.address, /* sender */
			callee,                /* receiver */
			if value > 0 { Some(value.into()) } else { None },
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
			MessageCallResult::Success(gas_left, return_data)
			| MessageCallResult::Reverted(gas_left, return_data) => {
				// cannot overflow, before making call gas_counter was incremented with gas, and gas_left < gas
				let gas_used = gas_left.low_u64() * self.ext.schedule().wasm().opcodes_div as u64
					/ self.ext.schedule().wasm().opcodes_mul as u64;
				let gas_left = match self.gas_counter.checked_sub(gas_used) {
					Some(gas_left) => gas_left,
					None => {
						receipt.outcome = TransactionOutcome::InsufficientGas;
						receipt.gas_used = self.gas_limit;
						return receipt;
					}
				};
				self.gas_counter -= gas_left;
				receipt.gas_used = gas_used;
				receipt.output = return_data;
				receipt.outcome = TransactionOutcome::Success;
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
	fn code_at(&self, addr: &Self::Address) -> Option<&[u8]> {
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
	fn account_meta_at(&self, addr: &Self::Address) -> Option<Self::AccountMeta> {
		Some(Self::AccountMeta {
			balance: match self.ext.balance(maddr2eaddr(addr)) {
				Ok(bal) if bal.bits() <= 64 => bal.low_u64(),
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

pub fn maddr2eaddr(addr: &mantle_types::Address) -> &ethereum_types::Address {
	// this is safe because both `Address` types are newtypes containing [u8; 32]
	unsafe { std::mem::transmute(addr) }
}

pub fn eaddr2maddr(addr: &ethereum_types::Address) -> &mantle_types::Address {
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
		gas_limit: u64,
		args: Vec<u8>,
		context: RuntimeContext,
	) -> Runtime {
		Runtime {
			bcfs: UnsafeCell::new(BCFS::new(*eaddr2maddr(&context.address), "oasis")),
			gas_counter: 0,
			gas_limit,
			ext,
			context,
			args,
			output: Vec::new(),
			err_output: Vec::new(),
			should_revert: false,
			should_persist: false,
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
		unsafe { &mut *self.bcfs.get() }.sync(&mut self);
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

	fn do_read(
		&mut self,
		ctx: &mut Ctx,
		fd: Fd,
		iovs: P<IoVec>,
		iovs_len: Size,
		offset: Option<FileSize>,
		nread: P<Size>,
	) -> Result<u16> {
		let iovs: &[IoVec] = self.memory_get(ctx, iovs, iovs_len as usize)?;
		let mut ioslices = iovs
			.iter()
			.map(|iov| {
				let mem_slice = self.memory_get_mut::<_, u8>(ctx, iov.buf, iov.len as usize)?;
				let p = mem_slice.as_mut_ptr();
				std::mem::forget(mem_slice);
				// Launder the slice to get around borrow of `self` by `iovs` so that
				// it can be used by `bcfs` via `PendingTransaction`.
				Ok(std::io::IoSliceMut::new(unsafe {
					std::slice::from_raw_parts_mut(p, iov.len as usize)
				}))
			})
			.collect::<std::result::Result<Vec<_>, wasmi::Error>>()?;

		let nbytes = match offset {
			Some(offset) => bcfs!(self.bcfs.pread_vectored(fd, &mut ioslices, offset)),
			None => bcfs!(self.bcfs.read_vectored(fd, &mut ioslices)),
		};

		// Charge sload gas, scaled by number of bytes.
		let sload_gas = U256::from(self.schedule().sload_gas);
		let bytes_len = U256::from(nbytes);

		// gas <- ceiling(sload_gas * bytes_len / 32)
		// Cannot overflow as gas and len are converted from u64s.
		let mut gas = sload_gas * bytes_len / U256::from(32);
		if sload_gas * bytes_len % U256::from(32) != U256::from(0) {
			gas = gas + U256::from(1);
		}

		// Charge gas after checking for u64 overflow.
		if gas > U256::from(std::u64::MAX) {
			return Err(crate::runtime::Error::GasLimit);
		} else {
			self.adjusted_charge(|_| Some(gas.as_u64()))?;
		}

		self.memory_set_value(
			ctx,
			nread,
			match nbytes.try_into() {
				Ok(nbytes) => nbytes,
				Err(_) => return Ok(ErrNo::MFile as u16),
			},
		)?;

		Ok(ErrNo::Success as u16)
	}

	fn do_write(
		&mut self,
		ctx: &mut Ctx,
		fd: Fd,
		iovs: P<IoVec>,
		iovs_len: Size,
		offset: Option<FileSize>,
		nwritten: P<u32>,
	) -> Result<u16> {
		// TODO: refunds
		let iovs: &[IoVec] = self.memory_get_mut(ctx, iovs, iovs_len as usize)?;
		let ioslices = iovs
			.iter()
			.map(|iov| {
				let mem_slice = self.memory_get::<_, u8>(ctx, iov.buf, iov.len as usize)?;
				let p = mem_slice.as_ptr();
				std::mem::forget(mem_slice);
				// Launder the slice to get around borrow of `self` by `iovs` so that
				// it can be used by `bcfs` via `PendingTransaction`.
				Ok(std::io::IoSlice::new(unsafe {
					std::slice::from_raw_parts(p, iov.len as usize)
				}))
			})
			.collect::<std::result::Result<Vec<_>, wasmi::Error>>()?;

		let nbytes = match offset {
			Some(offset) => bcfs!(self.bcfs.pwrite_vectored(fd, &ioslices, offset)),
			None => bcfs!(self.bcfs.write_vectored(fd, &ioslices)),
		};
		self.storage_bytes_charge(nbytes as u64, true /* reset */)?;
		self.storage_bytes_charge(nbytes as u64, false /* reset */)?;
		self.memory_set_value(
			ctx,
			nwritten,
			match nbytes.try_into() {
				Ok(nbytes) => nbytes,
				Err(_) => return Ok(ErrNo::MFile as u16),
			},
		)?;
		Ok(ErrNo::Success as u16)
	}

	fn memory_get<O: Into<u32>, T: Copy>(
		&self,
		ctx: &mut Ctx,
		offset: O,
		count: usize,
	) -> Result<&[T]> {
		Ok(&*self.memory_get_mut(ctx, offset, count)?)
	}

	fn memory_get_mut<O: Into<u32>, T: Copy>(
		&self,
		ctx: &mut Ctx,
		ptr: O,
		count: usize,
	) -> Result<&mut [T]> {
		let offset = ptr.into() as usize;
		let mut mem_get_bytes = &ctx.memory(0).view()[offset..(offset + count)];

		let mem_slice =
			unsafe { std::mem::transmute::<&[std::cell::Cell<u8>], &[u8]>(mem_get_bytes) };

		Ok(unsafe { core::slice::from_raw_parts_mut(mem_slice.as_ptr() as *mut T, count) })
	}

	fn memory_set<T: Copy, O: Into<P<T>>>(
		&self,
		ctx: &mut Ctx,
		ptr: O,
		value: &[T],
	) -> Result<P<T>> {
		let ptr = ptr.into();
		let offset = ptr.offset() as usize;
		let nbytes = value.len();

		let byte_buf = unsafe {
			std::slice::from_raw_parts(value.as_ptr() as *const u8, nbytes)
		};

		ctx.memory(0).view()[offset..(offset + nbytes)]
			.iter()
			.zip(byte_buf.iter())
			.for_each(|(cell, v)| cell.set(*v));

		Ok(P {
			offset: ptr.offset() + nbytes as u32,
			ty: std::marker::PhantomData,
		})
	}

	fn memory_set_value<T: Sized, O: Into<P<T>>>(
		&mut self,
		ctx: &mut Ctx,
		ptr: O,
		value: T,
	) -> Result<()> {
		let t_size = std::mem::size_of::<T>();
		let offset = ptr.into().offset() as usize;
		unsafe {
			let byte_buf: &[u8] =
				std::slice::from_raw_parts(&value as *const _ as *const u8, t_size);
			ctx.memory(0).view()[offset..(offset + t_size)]
				.iter()
				.zip(byte_buf.iter())
				.for_each(|(cell, v)| cell.set(*v));
		}
		Ok(())
	}

	fn memory_zero(&mut self, ctx: &mut Ctx, offset: u32, len: usize) -> Result<()> {
		ctx.memory(0).view()[offset as usize..(offset as usize + len)]
			.iter()
			.for_each(|cell| cell.set(0u8));
		Ok(())
	}

	pub fn args_get(&mut self, ctx: &mut Ctx, argv: P<P<u8>>, argv_buf: P<u8>) -> Result<u16> {
		Ok(ErrNo::Success as u16)
	}

	pub fn args_sizes_get(
		&mut self,
		ctx: &mut Ctx,
		argc: P<u32>,
		_argv_buf_size: P<u32>,
	) -> Result<u16> {
		let memory = ctx.memory(0);
		self.memory_set_value(ctx, argc, 0);

		Ok(ErrNo::Success as u16)
	}

	pub fn fd_prestat_get(&mut self, ctx: &mut Ctx, fd: u32, buf: P<Prestat>) -> Result<u16> {
		let memory = ctx.memory(0);
		let fd_val = Fd::try_from(fd).unwrap();
		let path_str = bcfs!(self.bcfs.prestat(fd_val)).to_str().unwrap();

		self.memory_set_value(
			ctx,
			buf,
			Prestat {
				resource_type: PreopenType::Dir {
					name_len: match path_str.len().try_into() {
						Ok(name_len) => name_len,
						Err(_) => return Ok(ErrNo::NameTooLong as u16),
					},
				},
			},
		)
		.unwrap();
		Ok(ErrNo::Success as u16)
	}

	pub fn fd_prestat_dir_name(
		&mut self,
		ctx: &mut Ctx,
		fd: u32,
		path_ptr: P<u8>,
		path_len: u32,
	) -> Result<u16> {
		let memory = ctx.memory(0);
		let fd_val = Fd::try_from(fd).unwrap();
		let path_str = bcfs!(self.bcfs.prestat(fd_val)).to_str().unwrap();

		self.memory_set(ctx, path_ptr, path_str.as_bytes()).unwrap();
		self.memory_set_value(ctx, path_len, path_str.len() as u8)
			.unwrap();
		Ok(ErrNo::Success as u16)
	}

	pub fn environ_get(
		&mut self,
		ctx: &mut Ctx,
		environ: P<P<u8>>,
		mut environ_buf: P<u8>,
	) -> Result<u16> {
		let environs = self.memory_get_mut::<_, P<u8>>(ctx, environ, 3).unwrap();

		environs[0] = environ_buf;
		environ_buf = self
			.memory_set(
				ctx,
				environ_buf,
				format!("ADDRESS={:x}\0", self.context.address).as_bytes(),
			)
			.unwrap();
		environs[1] = environ_buf;
		environ_buf = self
			.memory_set(
				ctx,
				environ_buf,
				format!("SENDER={:x}\0", self.context.sender).as_bytes(),
			)
			.unwrap();
		environs[2] = environ_buf;
		self.memory_set(
			ctx,
			environ_buf,
			format!("VALUE={}", self.context.value_str).as_bytes(),
		)
		.unwrap();
		Ok(ErrNo::Success as u16)
	}

	pub fn environ_sizes_get(
		&mut self,
		ctx: &mut Ctx,
		environ_count: P<u32>,
		environ_buf_size: P<u32>,
	) -> Result<u16> {
		self.memory_set_value(ctx, environ_count, 3u32)?; // sender, address, value
		self.memory_set_value(
			ctx,
			environ_buf_size,
			("SENDER=".len()
				+ ADDR_CHARS + "\0ADDRESS=".len()
				+ ADDR_CHARS + "\0VALUE=".len()
				+ self.context.value_str.len()) as u32,
		)
		.unwrap();
		Ok(ErrNo::Success as u16)
	}

	pub fn fd_read(
		&mut self,
		ctx: &mut Ctx,
		fd: u32,
		iovs: P<IoVec>,
		iovs_len: u32,
		nread: P<Size>,
	) -> Result<u16> {
		let fd_val = Fd::try_from(fd).unwrap();
		self.do_read(
			ctx,
			fd_val,
			iovs,
			Size::try_from(iovs_len).unwrap(),
			None,
			nread,
		)
	}

	pub fn fd_write(
		&mut self,
		ctx: &mut Ctx,
		fd: u32,
		iovs: P<IoVec>,
		iovs_len: u32,
		nwritten: P<u32>,
	) -> Result<u16> {
		let fd_val = Fd::try_from(fd).unwrap();
		self.do_write(
			ctx,
			fd_val,
			iovs,
			Size::try_from(iovs_len).unwrap(),
			None,
			nwritten,
		)
	}

	pub fn fd_close(&mut self, ctx: &mut Ctx, fd: u32) -> Result<u16> {
		let fd_val = Fd::try_from(fd).unwrap();
		bcfs!(self.bcfs.close(fd_val));
		Ok(ErrNo::Success as u16)
	}

	pub fn fd_fdstat_get(&mut self, ctx: &mut Ctx, fd: u32, buf: P<FdStat>) -> Result<u16> {
		let fd_val = Fd::try_from(fd).unwrap();
		let stats = bcfs!(self.bcfs.fdstat(fd_val));
		self.memory_set_value(ctx, buf, stats).unwrap();
		Ok(ErrNo::Success as u16)
	}

	pub fn fd_filestat_get(&mut self, ctx: &mut Ctx, fd: u32, buf: P<FileStat>) -> Result<u16> {
		let fd_val = Fd::try_from(fd).unwrap();
		self.memory_set_value(ctx, buf, bcfs!(self.bcfs.filestat(fd_val)))?;
		Ok(ErrNo::Success as u16)
	}

	pub fn proc_exit(&mut self, ctx: &mut Ctx, rval: u32) -> Result<u16> {
		self.should_persist = (rval == 0);
		Err(crate::runtime::Error::Return)
	}

	pub fn path_open(
		&mut self,
		ctx: &mut Ctx,
		dir_fd: u32,
		_dir_flags: u32,
		path: P<u8>,
		path_len: u32,
		open_flags: u16,
		_rights_base: u64,
		_rights_inheriting: u64,
		fd_flags: u16,
		p_fd: P<Fd>,
	) -> Result<u16> {
		let path = std::path::Path::new(
			// NB: immutable borrow of `self`
			match std::str::from_utf8(self.memory_get(ctx, path, path_len as usize)?) {
				Ok(path_str) => path_str,
				Err(_) => return Ok(ErrNo::Inval as u16),
			},
		);
		let path_ptr = path as *const std::path::Path;
		std::mem::forget(path);
		let path = unsafe { &*path_ptr }; // aliasing is safe as BCFS doesn't disturb linear memory

		// Convert from primatives to wasi_types
		let dir_fd_val = Fd::try_from(dir_fd).unwrap();
		let open_flags_val = OpenFlags::from_bits(open_flags).unwrap();
		let fd_flags_val = FdFlags::from_bits(fd_flags).unwrap();

		let fd = bcfs!(self // NB: mutable borrow of `self as PendingTransaction``
			.bcfs
			.open(dir_fd_val, path, open_flags_val, fd_flags_val));
		self.memory_set_value(ctx, p_fd, fd)?;
		Ok(ErrNo::Success as u16)
	}

	pub fn path_unlink_file(
		&mut self,
		ctx: &mut Ctx,
		dir_fd: u32,
		path: P<u8>,
		path_len: u32,
	) -> Result<u16> {
		let path = std::path::Path::new(
			// NB: immutable borrow of `self`
			match std::str::from_utf8(self.memory_get(ctx, path, path_len as usize)?) {
				Ok(path_str) => path_str,
				Err(_) => return Ok(ErrNo::Inval as u16),
			},
		);
		let path_ptr = path as *const std::path::Path;
		std::mem::forget(path);
		let path = unsafe { &*path_ptr }; // aliasing is safe as BCFS doesn't disturb linear memory

		let dir_fd_val = Fd::try_from(dir_fd).unwrap();
		let prev_len = bcfs!(self.bcfs.unlink(dir_fd_val, path));

		self.ext
			.inc_sstore_clears(prev_len as u64)
			.map_err(|_| crate::runtime::Error::StorageUpdateError)?;
		Ok(ErrNo::Success as u16)
	}
}

pub mod imports {

	use super::{Memory, Result, Runtime, P};
	use std::ffi::c_void;
	use wasi_types::*;
	use wasmer_runtime::{func, Ctx};

	pub(crate) fn get_import_object(
		memory: Memory,
		raw_ptr: *mut c_void,
	) -> wasmer_runtime::ImportObject {
		let dtor = (|_: *mut c_void| {}) as fn(*mut c_void);
		wasmer_runtime::imports! {
			move || { (raw_ptr, dtor) },
			"env" => {
				"memory" => memory,
			},
			"wasi_unstable" => {
				"args_get" => func!(args_get),
				"args_sizes_get" => func!(args_sizes_get),
				"fd_prestat_get" => func!(fd_prestat_get),
				"fd_prestat_dir_name" => func!(fd_prestat_dir_name),
				"environ_get" => func!(environ_get),
				"environ_sizes_get" => func!(environ_sizes_get),
				"fd_fdstat_get" => func!(fd_fdstat_get),
				"fd_filestat_get" => func!(fd_filestat_get),
				"fd_read" => func!(fd_read),
				"fd_write" => func!(fd_write),
				"fd_close" => func!(fd_close),
				"proc_exit" => func!(proc_exit),
				"path_open" => func!(path_open),
				"path_unlink_file" => func!(path_unlink_file),
			},
		}
	}

	fn args_get(ctx: &mut Ctx, argv: P<P<u8>>, argv_buf: P<u8>) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.args_get(ctx, argv, argv_buf)
	}

	fn args_sizes_get(ctx: &mut Ctx, argv: P<u32>, argv_buf_size: P<u32>) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.args_sizes_get(ctx, argv, argv_buf_size)
	}

	fn fd_prestat_get(ctx: &mut Ctx, fd: u32, buf: P<Prestat>) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_prestat_get(ctx, fd, buf)
	}

	fn fd_prestat_dir_name(ctx: &mut Ctx, fd: u32, path_ptr: P<u8>, path_len: u32) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_prestat_dir_name(ctx, fd, path_ptr, path_len)
	}

	fn environ_get(ctx: &mut Ctx, environ: P<P<u8>>, mut environ_buf: P<u8>) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.environ_get(ctx, environ, environ_buf)
	}

	fn environ_sizes_get(
		ctx: &mut Ctx,
		environ_count: P<u32>,
		environ_buf_size: P<u32>,
	) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.environ_sizes_get(ctx, environ_count, environ_buf_size)
	}

	fn fd_read(
		ctx: &mut Ctx,
		fd: u32,
		iovs: P<IoVec>,
		iovs_len: u32,
		nread: P<Size>,
	) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_read(ctx, fd, iovs, iovs_len, nread)
	}

	fn fd_write(
		ctx: &mut Ctx,
		fd: u32,
		iovs: P<IoVec>,
		iovs_len: u32,
		nwritten: P<u32>,
	) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_write(ctx, fd, iovs, iovs_len, nwritten)
	}

	fn fd_close(ctx: &mut Ctx, fd: u32) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_close(ctx, fd)
	}

	fn fd_fdstat_get(ctx: &mut Ctx, fd: u32, buf: P<FdStat>) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_fdstat_get(ctx, fd, buf)
	}

	pub fn fd_filestat_get(ctx: &mut Ctx, fd: u32, buf: P<FileStat>) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_filestat_get(ctx, fd, buf)
	}

	fn proc_exit(ctx: &mut Ctx, rval: u32) -> Result<()> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.proc_exit(ctx, rval);
		Ok(())
	}

	fn path_open(
		ctx: &mut Ctx,
		dir_fd: u32,
		dir_flags: u32,
		path: P<u8>,
		path_len: u32,
		open_flags: u16,
		rights_base: u64,
		rights_inheriting: u64,
		fd_flags: u16,
		p_fd: P<Fd>,
	) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.path_open(
			ctx,
			dir_fd,
			dir_flags,
			path,
			path_len,
			open_flags,
			rights_base,
			rights_inheriting,
			fd_flags,
			p_fd,
		)
	}

	fn path_unlink_file(ctx: &mut Ctx, dir_fd: u32, path: P<u8>, path_len: u32) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.path_unlink_file(ctx, dir_fd, path, path_len)
	}

}
