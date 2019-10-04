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

use wasi_types::*;
use wasmer_runtime_core::func;
use wasmer_runtime_core::memory::ptr::{Array, Item, WasmPtr};
use wasmer_runtime_core::memory::Memory;
use wasmer_runtime_core::types::WasmExternType;
use wasmer_runtime_core::vm::Ctx;

const ADDR_LEN_BYTES: usize = std::mem::size_of::<oasis_types::Address>();
const ADDR_CHARS: usize = ADDR_LEN_BYTES * 2; // two hex digits per byte

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
	pub bcfs: UnsafeCell<BCFS>,
	pub should_revert: bool,
	// Needed for wasmer since only generic CallError is returned on panic/exit
	pub should_persist: bool,
	pub bytes_cache: RefCell<Vec<Arc<Vec<u8>>>>,
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

pub mod imports {

	use super::{func, Array, Ctx, Item, Memory, Result, Runtime, WasmPtr};
	use std::ffi::c_void;
	use wasi_types::*;
	use wasmer_runtime_core;

	pub(crate) fn get_import_object(
		memory: Memory,
		raw_ptr: *mut c_void,
	) -> wasmer_runtime_core::import::ImportObject {
		let dtor = (|_: *mut c_void| {}) as fn(*mut c_void);

		wasmer_runtime_core::imports! {
			move || { (raw_ptr, dtor) },
			"env" => {
				"memory" => memory,
			},
			"wasi_unstable" => {
				"args_get" => func!(args_get),
				"args_sizes_get" => func!(args_sizes_get),
				"clock_res_get" => func!(clock_res_get),
				"clock_time_get" => func!(clock_time_get),
				"environ_get" => func!(environ_get),
				"environ_sizes_get" => func!(environ_sizes_get),
				"fd_advise" => func!(fd_advise),
				"fd_allocate" => func!(fd_allocate),
				"fd_close" => func!(fd_close),
				"fd_datasync" => func!(fd_datasync),
				"fd_fdstat_get" => func!(fd_fdstat_get),
				"fd_fdstat_set_flags" => func!(fd_fdstat_set_flags),
				"fd_fdstat_set_rights" => func!(fd_fdstat_set_rights),
				"fd_filestat_get" => func!(fd_filestat_get),
				"fd_filestat_set_size" => func!(fd_filestat_set_size),
				"fd_filestat_set_times" => func!(fd_filestat_set_times),
				"fd_pread" => func!(fd_pread),
				"fd_prestat_dir_name" => func!(fd_prestat_dir_name),
				"fd_prestat_get" => func!(fd_prestat_get),
				"fd_pwrite" => func!(fd_pwrite),
				"fd_read" => func!(fd_read),
				"fd_readdir" => func!(fd_readdir),
				"fd_renumber" => func!(fd_renumber),
				"fd_seek" => func!(fd_seek),
				"fd_sync" => func!(fd_sync),
				"fd_tell" => func!(fd_tell),
				"fd_write" => func!(fd_write),
				"path_create_directory" => func!(path_create_directory),
				"path_filestat_get" => func!(path_filestat_get),
				"path_filestat_set_times" => func!(path_filestat_set_times),
				"path_link" => func!(path_link),
				"path_open" => func!(path_open),
				"path_readlink" => func!(path_readlink),
				"path_remove_directory" => func!(path_remove_directory),
				"path_rename" => func!(path_rename),
				"path_unlink_file" => func!(path_unlink_file),
				"path_symlink" => func!(path_symlink),
				"poll_oneoff" => func!(poll_oneoff),
				"proc_exit" => func!(proc_exit),
				"proc_raise" => func!(proc_raise),
				"random_get" => func!(random_get),
				"sched_yield" => func!(sched_yield),
			},
		}
	}

	fn args_get(
		ctx: &mut Ctx,
		argv: WasmPtr<WasmPtr<u8, Array>, Array>,
		argv_buf: WasmPtr<u8, Array>,
	) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.args_get(ctx, argv, argv_buf)
	}

	fn args_sizes_get(
		ctx: &mut Ctx,
		argv: WasmPtr<u32>,
		argv_buf_size: WasmPtr<u32>,
	) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.args_sizes_get(ctx, argv, argv_buf_size)
	}

	fn clock_res_get(ctx: &mut Ctx, clock_id: u8, resolution: WasmPtr<Timestamp>) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.clock_res_get(ctx, clock_id, resolution)
	}

	fn clock_time_get(
		ctx: &mut Ctx,
		clock_id: u8,
		precision: u64,
		time: WasmPtr<Timestamp>,
	) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.clock_time_get(ctx, clock_id, precision, time)
	}

	fn environ_get(
		ctx: &mut Ctx,
		environ: WasmPtr<WasmPtr<u8>>,
		mut environ_buf: WasmPtr<u8>,
	) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.environ_get(ctx, environ, environ_buf)
	}

	fn environ_sizes_get(
		ctx: &mut Ctx,
		environ_count: WasmPtr<u32>,
		environ_buf_size: WasmPtr<u32>,
	) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.environ_sizes_get(ctx, environ_count, environ_buf_size)
	}

	fn fd_advise(ctx: &mut Ctx, fd: u32, offset: u64, len: u64, advice: u8) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_advise(fd, offset, len, advice)
	}

	fn fd_allocate(ctx: &mut Ctx, fd: u32, offset: u64, len: u64) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_allocate(fd, offset, len)
	}

	fn fd_close(ctx: &mut Ctx, fd: u32) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_close(ctx, fd)
	}

	fn fd_datasync(ctx: &mut Ctx, fd: u32) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_datasync(fd)
	}

	fn fd_fdstat_get(ctx: &mut Ctx, fd: u32, buf: WasmPtr<FdStat>) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_fdstat_get(ctx, fd, buf)
	}

	fn fd_fdstat_set_flags(ctx: &mut Ctx, fd: u32, flags: u16) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_fdstat_set_flags(fd, flags)
	}

	fn fd_fdstat_set_rights(
		ctx: &mut Ctx,
		fd: u32,
		rights_base: u64,
		rights_inheriting: u64,
	) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_fdstat_set_rights(fd, rights_base, rights_inheriting)
	}

	fn fd_filestat_get(ctx: &mut Ctx, fd: u32, buf: WasmPtr<FileStat>) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_filestat_get(ctx, fd, buf)
	}

	fn fd_filestat_set_size(ctx: &mut Ctx, fd: u32, size: u64) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_filestat_set_size(fd, size)
	}

	fn fd_filestat_set_times(
		ctx: &mut Ctx,
		fd: u32,
		atime: u64,
		mtime: u64,
		flags: u16,
	) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_filestat_set_times(fd, atime, mtime, flags)
	}

	fn fd_pread(
		ctx: &mut Ctx,
		fd: u32,
		iovs: WasmPtr<IoVec, Array>,
		iovs_len: u32,
		offset: u64,
		nread: WasmPtr<Size, Array>,
	) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_pread(ctx, fd, iovs, iovs_len, offset, nread)
	}

	fn fd_prestat_get(ctx: &mut Ctx, fd: u32, buf: WasmPtr<Prestat>) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_prestat_get(ctx, fd, buf)
	}

	fn fd_prestat_dir_name(
		ctx: &mut Ctx,
		fd: u32,
		path_ptr: WasmPtr<u8>,
		path_len: u32,
	) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_prestat_dir_name(ctx, fd, path_ptr, path_len)
	}

	fn fd_pwrite(
		ctx: &mut Ctx,
		fd: u32,
		iovs: WasmPtr<IoVec>,
		iovs_len: u32,
		offset: u64,
		nwritten: WasmPtr<Size>,
	) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_pwrite(ctx, fd, iovs, iovs_len, offset, nwritten)
	}

	fn fd_read(
		ctx: &mut Ctx,
		fd: u32,
		iovs: WasmPtr<IoVec, Array>,
		iovs_len: u32,
		nread: WasmPtr<Size, Array>,
	) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_read(ctx, fd, iovs, iovs_len, nread)
	}

	fn fd_readdir(
		ctx: &mut Ctx,
		fd: u32,
		buf: WasmPtr<u8>,
		buf_len: u32,
		dircookie: u64,
		buf_used: WasmPtr<u32>,
	) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_readdir(fd, buf, buf_len, dircookie, buf_used)
	}

	fn fd_renumber(ctx: &mut Ctx, to: u32, from: u32) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_renumber(to, from)
	}

	fn fd_seek(
		ctx: &mut Ctx,
		fd: u32,
		offset: i64,
		whence: u8,
		new_offset: WasmPtr<FileSize>,
	) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_seek(ctx, fd, offset, whence, new_offset)
	}

	fn fd_sync(ctx: &mut Ctx, fd: u32) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_sync(fd)
	}

	fn fd_tell(ctx: &mut Ctx, fd: u32, offset: WasmPtr<FileSize>) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_tell(ctx, fd, offset)
	}

	fn fd_write(
		ctx: &mut Ctx,
		fd: u32,
		iovs: WasmPtr<IoVec>,
		iovs_len: u32,
		nwritten: WasmPtr<u32>,
	) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.fd_write(ctx, fd, iovs, iovs_len, nwritten)
	}

	fn path_create_directory(
		ctx: &mut Ctx,
		fd: u32,
		path: WasmPtr<u8>,
		path_len: u32,
	) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.path_create_directory(fd, path, path_len)
	}

	fn path_filestat_get(
		ctx: &mut Ctx,
		fd: u32,
		lookup_flags: u32,
		path: WasmPtr<u8>,
		path_len: u32,
		filestat_buf: WasmPtr<FileStat>,
	) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.path_filestat_get(fd, lookup_flags, path, path_len, filestat_buf)
	}

	pub fn path_filestat_set_times(
		ctx: &mut Ctx,
		fd: u32,
		lookup_flags: u32,
		path: WasmPtr<u8>,
		path_len: u32,
		atime: u64,
		mtime: u64,
		fstflags: u16,
	) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.path_filestat_set_times(fd, lookup_flags, path, path_len, atime, mtime, fstflags)
	}

	pub fn path_link(
		ctx: &mut Ctx,
		old_fd: u32,
		old_lookup_flags: u32,
		old_path: WasmPtr<u8>,
		old_path_len: u32,
		new_fd: u32,
		new_path: WasmPtr<u8>,
		new_path_len: u32,
	) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.path_link(
			old_fd,
			old_lookup_flags,
			old_path,
			old_path_len,
			new_fd,
			new_path,
			new_path_len,
		)
	}

	fn path_open(
		ctx: &mut Ctx,
		dir_fd: u32,
		dir_flags: u32,
		path: WasmPtr<u8>,
		path_len: u32,
		open_flags: u16,
		rights_base: u64,
		rights_inheriting: u64,
		fd_flags: u16,
		p_fd: WasmPtr<Fd>,
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

	fn path_readlink(
		ctx: &mut Ctx,
		path: WasmPtr<u8>,
		path_len: u32,
		buf: WasmPtr<u8>,
		buf_len: u32,
		buf_used: WasmPtr<u32>,
	) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.path_readlink(path, path_len, buf, buf_len, buf_used)
	}

	fn path_remove_directory(
		ctx: &mut Ctx,
		fd: u32,
		path: WasmPtr<u8>,
		path_len: u32,
	) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.path_remove_directory(fd, path, path_len)
	}

	fn path_rename(
		ctx: &mut Ctx,
		old_fd: u32,
		old_lookup_flags: u32,
		old_path: WasmPtr<u8>,
		old_path_len: u32,
		new_fd: u32,
		new_path: WasmPtr<u8>,
		new_path_len: u32,
	) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.path_rename(
			old_fd,
			old_lookup_flags,
			old_path,
			old_path_len,
			new_fd,
			new_path,
			new_path_len,
		)
	}

	fn path_symlink(
		ctx: &mut Ctx,
		from_path: WasmPtr<u8>,
		from_path_len: u32,
		rel_fd: u32,
		to_path: WasmPtr<u8>,
		to_path_len: u32,
	) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.path_symlink(from_path, from_path_len, rel_fd, to_path, to_path_len)
	}

	fn path_unlink_file(
		ctx: &mut Ctx,
		dir_fd: u32,
		path: WasmPtr<u8, Array>,
		path_len: u32,
	) -> Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.path_unlink_file(ctx, dir_fd, path, path_len)
	}

	fn poll_oneoff(
		ctx: &mut Ctx,
		ptr_in: WasmPtr<u32>,
		ptr_out: WasmPtr<u32>,
		n_subs: u32,
	) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.poll_oneoff(ptr_in, ptr_out, n_subs)
	}

	fn proc_exit(ctx: &mut Ctx, rval: u32) -> Result<()> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.proc_exit(ctx, rval);
		Ok(())
	}

	fn proc_raise(ctx: &mut Ctx, sig: u8) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.proc_raise(sig)
	}

	fn random_get(ctx: &mut Ctx, buf: WasmPtr<u8>, buf_len: u32) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.random_get(buf, buf_len)
	}

	fn sched_yield(ctx: &mut Ctx) -> crate::Result<u16> {
		let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
		runtime.sched_yield()
	}
}
