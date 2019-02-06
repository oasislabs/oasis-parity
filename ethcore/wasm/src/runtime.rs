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
use std::mem;

use ethereum_types::{U256, H256, Address};
use hash;
use vm::{self, CallType};
use wasmi::{self, MemoryRef, RuntimeArgs, RuntimeValue, Error as InterpreterError, Trap, TrapKind};
use super::panic_payload;

pub struct RuntimeContext {
	pub address: Address,
	pub sender: Address,
	pub origin: Address,
	pub code_address: Address,
	pub value: U256,
}

pub struct Runtime<'a> {
	gas_counter: u64,
	gas_limit: u64,
	ext: &'a mut vm::Ext,
	context: RuntimeContext,
	memory: MemoryRef,
	args: Vec<u8>,
	result: Vec<u8>,
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

impl wasmi::HostError for Error { }

impl From<Trap> for Error {
	fn from(trap: Trap) -> Self {
		match *trap.kind() {
			TrapKind::Unreachable => Error::Unreachable,
			TrapKind::MemoryAccessOutOfBounds => Error::MemoryAccessViolation,
			TrapKind::TableAccessOutOfBounds | TrapKind::ElemUninitialized => Error::InvalidVirtualCall,
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

type Result<T> = ::std::result::Result<T, Error>;

impl<'a> Runtime<'a> {

	/// New runtime for wasm contract with specified params
	pub fn with_params(
		ext: &mut vm::Ext,
		memory: MemoryRef,
		gas_limit: u64,
		args: Vec<u8>,
		context: RuntimeContext,
	) -> Runtime {
		Runtime {
			gas_counter: 0,
			gas_limit: gas_limit,
			memory: memory,
			ext: ext,
			context: context,
			args: args,
			result: Vec::new(),
		}
	}

	/// Loads 256-bit hash from the specifed sandboxed memory pointer
	fn h256_at(&self, ptr: u32) -> Result<H256> {
		let mut buf = [0u8; 32];
		self.memory.get_into(ptr, &mut buf[..])?;

		Ok(H256::from(&buf[..]))
	}

	/// Loads 160-bit hash (Ethereum address) from the specified sandboxed memory pointer
	fn address_at(&self, ptr: u32) -> Result<Address> {
		let mut buf = [0u8; 20];
		self.memory.get_into(ptr, &mut buf[..])?;

		Ok(Address::from(&buf[..]))
	}

	/// Loads 256-bit integer represented with bigendian from the specified sandboxed memory pointer
	fn u256_at(&self, ptr: u32) -> Result<U256> {
		let mut buf = [0u8; 32];
		self.memory.get_into(ptr, &mut buf[..])?;

		Ok(U256::from_big_endian(&buf[..]))
	}

	/// Charge specified amount of gas
	///
	/// Returns false if gas limit exceeded and true if not.
	/// Intuition about the return value sense is to aswer the question 'are we allowed to continue?'
	fn charge_gas(&mut self, amount: u64) -> bool {
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

	/// Charge gas according to closure
	pub fn charge<F>(&mut self, f: F) -> Result<()>
		where F: FnOnce(&vm::Schedule) -> u64
	{
		let amount = f(self.ext.schedule());
		if !self.charge_gas(amount as u64) {
			Err(Error::GasLimit)
		} else {
			Ok(())
		}
	}

	/// Adjusted charge of gas which scales actual charge according to the wasm opcode counting coefficient
	pub fn adjusted_charge<F>(&mut self, f: F) -> Result<()>
		where F: FnOnce(&vm::Schedule) -> u64
	{
		self.charge(|schedule| f(schedule) * schedule.wasm().opcodes_div as u64 / schedule.wasm().opcodes_mul as u64)
	}

	/// Charge gas provided by the closure
	///
	/// Closure also can return overflowing flag as None in gas cost.
	pub fn overflow_charge<F>(&mut self, f: F) -> Result<()>
		where F: FnOnce(&vm::Schedule) -> Option<u64>
	{
		let amount = match f(self.ext.schedule()) {
			Some(amount) => amount,
			None => { return Err(Error::GasLimit.into()); }
		};

		if !self.charge_gas(amount as u64) {
			Err(Error::GasLimit.into())
		} else {
			Ok(())
		}
	}

	/// Same as overflow_charge, but with amount adjusted by wasm opcodes coeff
	pub fn adjusted_overflow_charge<F>(&mut self, f: F) -> Result<()>
		where F: FnOnce(&vm::Schedule) -> Option<u64>
	{
		self.overflow_charge(|schedule|
			f(schedule)
				.and_then(|x| x.checked_mul(schedule.wasm().opcodes_div as u64))
				.map(|x| x / schedule.wasm().opcodes_mul as u64)
		)
	}

	/// Read from the storage to wasm memory
	/// All storage read through here *must* be an H256.
	pub fn storage_read(&mut self, args: RuntimeArgs) -> Result<()>
	{
		let key = self.h256_at(args.nth_checked(0)?)?;
		let val_ptr: u32 = args.nth_checked(1)?;

		let val = self.ext.storage_at(&key).map_err(|_| Error::StorageReadError)?;

		self.adjusted_charge(|schedule| schedule.sload_gas as u64)?;

		self.memory.set(val_ptr as u32, &*val)?;

		Ok(())
	}

	/// Write to storage from wasm memory
	/// All storage written through here *must* be an H256.
	pub fn storage_write(&mut self, args: RuntimeArgs) -> Result<()>
	{
		let key = self.h256_at(args.nth_checked(0)?)?;
		let val_ptr: u32 = args.nth_checked(1)?;
		let val = self.h256_at(val_ptr)?;

		let former_val = self.ext.storage_at(&key).map_err(|_| Error::StorageUpdateError)?;
		let reset = !(former_val == H256::zero() && val != H256::zero());
		self.storage_bytes_charge(val.len() as u64, reset)?;

		self.ext.set_storage(key, val).map_err(|_| Error::StorageUpdateError)?;

		if former_val != H256::zero() && val == H256::zero() {
			self.ext.inc_sstore_clears(former_val.len() as u64).map_err(|_| Error::StorageUpdateError)?;
		}

		Ok(())
	}

	/// Gas charge prorated based on time until expiry and the number of bytes we're storing.
	fn storage_bytes_charge(&mut self, bytes_len: u64, reset: bool) -> Result<()> {
		let duration_secs = self.ext.seconds_until_expiry().map_err(|_| Error::StorageUpdateError)?;

		let gas = if !reset {
			self.ext.schedule().prorated_sstore_set_gas(duration_secs, bytes_len)
		} else {
			self.ext.schedule().prorated_sstore_reset_gas(duration_secs, bytes_len)
		};

		// Charge gas after checking for u64 overflow.
		if gas > U256::from(std::u64::MAX) {
			return Err(Error::GasLimit);
		} else {
			self.adjusted_charge(|_| gas.as_u64())?;
		}

		Ok(())
	}

	/// Return currently used schedule
	pub fn schedule(&self) -> &vm::Schedule {
		self.ext.schedule()
	}

	/// Sets a return value for the call
	///
	/// Syscall takes 2 arguments:
	/// * pointer in sandboxed memory where result is
	/// * the length of the result
	pub fn ret(&mut self, args: RuntimeArgs) -> Result<()> {
		let ptr: u32 = args.nth_checked(0)?;
		let len: u32 = args.nth_checked(1)?;

		trace!(target: "wasm", "Contract ret: {} bytes @ {}", len, ptr);

		self.result = self.memory.get(ptr, len as usize)?;

		Err(Error::Return)
	}

	/// Destroy the runtime, returning currently recorded result of the execution
	pub fn into_result(self) -> Vec<u8> {
		self.result
	}

	/// Query current gas left for execution
	pub fn gas_left(&self) -> Result<u64> {
		if self.gas_counter > self.gas_limit { return Err(Error::InvalidGasState); }
		Ok(self.gas_limit - self.gas_counter)
	}

	/// General gas charging extern.
	fn gas(&mut self, args: RuntimeArgs) -> Result<()> {
		let amount: u32 = args.nth_checked(0)?;
		if self.charge_gas(amount as u64) {
			Ok(())
		} else {
			Err(Error::GasLimit.into())
		}
	}

	/// Query the length of the input bytes
	fn input_legnth(&mut self) -> RuntimeValue {
		RuntimeValue::I32(self.args.len() as i32)
	}

	/// Write input bytes to the memory location using the passed pointer
	fn fetch_input(&mut self, args: RuntimeArgs) -> Result<()> {
		let ptr: u32 = args.nth_checked(0)?;

		let args_len = self.args.len() as u64;
		self.charge(|s| args_len * s.wasm().memcpy as u64)?;

		self.memory.set(ptr, &self.args[..])?;
		Ok(())
	}

	/// User panic
	///
	/// Contract can invoke this when he encounters unrecoverable error.
	fn panic(&mut self, args: RuntimeArgs) -> Result<()>
	{
		let payload_ptr: u32 = args.nth_checked(0)?;
		let payload_len: u32 = args.nth_checked(1)?;

		let raw_payload = self.memory.get(payload_ptr, payload_len as usize)?;
		let payload = panic_payload::decode(&raw_payload);
		let msg = format!(
			"{msg}, {file}:{line}:{col}",
			msg = payload
				.msg
				.as_ref()
				.map(String::as_ref)
				.unwrap_or("<msg was stripped>"),
			file = payload
				.file
				.as_ref()
				.map(String::as_ref)
				.unwrap_or("<unknown>"),
			line = payload.line.unwrap_or(0),
			col = payload.col.unwrap_or(0)
		);
		trace!(target: "wasm", "Contract custom panic message: {}", msg);

		Err(Error::Panic(msg).into())
	}

	/// Rust syscall
	fn syscall(&mut self, args: RuntimeArgs) -> Result<RuntimeValue>
	{
		let syscall_id: u32 = args.nth_checked(0)?;
		let data_ptr: u32 = args.nth_checked(1)?;
		Ok(match syscall_id {
			// https://github.com/rust-lang/rust/blob/master/src/etc/wasm32-shim.js
			1 => {
				let mem_bytes = self.memory.get(data_ptr, 4 * 3)?; // 3 words
				let payload = unsafe { mem::transmute::<Vec<u8>, Vec<u32>>(mem_bytes) };
				let out_str = String::from_utf8(
					self.memory.get(payload[1] as u32, payload[2] as usize)?)
					.map_err(|_| Error::BadUtf8)?;
				match payload[0] {
					1 => print!("{}", out_str),
					2 => print!("error: {}", out_str),
					_ => panic!("invalid output stream {}", payload[0])
				};
				1
			},
			2 => panic!("syscall exit with code {}", args.nth_checked::<u32>(1)?),
			3 => unimplemented!(), // args
			4 => 0, //unimplemented!(), // getenv
			5 => unreachable!(),   // doesn't exist?
			6 => unimplemented!(), // time
			_ => unimplemented!()
		}.into())
	}

	fn expf(&mut self, args: RuntimeArgs) -> Result<RuntimeValue> {
		let x: wasmi::nan_preserving_float::F32 = args.nth_checked(0)?;
		Ok(RuntimeValue::F32(wasmi::nan_preserving_float::F32::from_float(x.to_float().exp())))
	}

	fn do_call(
		&mut self,
		use_val: bool,
		call_type: CallType,
		args: RuntimeArgs,
	)
		-> Result<RuntimeValue>
	{
		trace!(target: "wasm", "runtime: CALL({:?})", call_type);

		let gas: u64 = args.nth_checked(0)?;
		trace!(target: "wasm", "           gas: {:?}", gas);

		let address = self.address_at(args.nth_checked(1)?)?;
		trace!(target: "wasm", "       address: {:?}", address);

		let vofs = if use_val { 1 } else { 0 };
		let val = if use_val { Some(self.u256_at(args.nth_checked(2)?)?) } else { None };
		trace!(target: "wasm", "           val: {:?}", val);

		let input_ptr: u32 = args.nth_checked(2 + vofs)?;
		trace!(target: "wasm", "     input_ptr: {:?}", input_ptr);

		let input_len: u32 = args.nth_checked(3 + vofs)?;
		trace!(target: "wasm", "     input_len: {:?}", input_len);

		let result_ptr: u32 = args.nth_checked(4 + vofs)?;
		trace!(target: "wasm", "    result_ptr: {:?}", result_ptr);

		let result_alloc_len: u32 = args.nth_checked(5 + vofs)?;
		trace!(target: "wasm", "    result_len: {:?}", result_alloc_len);

		if let Some(ref val) = val {
			let address_balance = self.ext.balance(&self.context.address)
				.map_err(|_| Error::BalanceQueryError)?;

			if &address_balance < val {
				trace!(target: "wasm", "runtime: call failed due to balance check");
				return Ok((-1i32).into());
			}
		}

		self.adjusted_charge(|schedule| schedule.call_gas as u64)?;

		let mut result = Vec::with_capacity(result_alloc_len as usize);
		result.resize(result_alloc_len as usize, 0);

		// todo: optimize to use memory views once it's in
		let payload = self.memory.get(input_ptr, input_len as usize)?;

		let adjusted_gas = match gas.checked_mul(self.ext.schedule().wasm().opcodes_div as u64)
			.map(|x| x / self.ext.schedule().wasm().opcodes_mul as u64)
		{
			Some(x) => x,
			None => {
				trace!("CALL overflowed gas, call aborted with error returned");
				return Ok(RuntimeValue::I32(-1))
			},
		};

		self.charge(|_| adjusted_gas)?;

		let call_result = self.ext.call(
			&gas.into(),
			match call_type { CallType::DelegateCall => &self.context.sender, _ => &self.context.address },
			match call_type { CallType::Call | CallType::StaticCall => &address, _ => &self.context.address },
			val,
			&payload,
			&address,
			&mut result[..],
			call_type,
		);

		match call_result {
			vm::MessageCallResult::Success(gas_left, _) => {
				// cannot overflow, before making call gas_counter was incremented with gas, and gas_left < gas
				self.gas_counter = self.gas_counter -
					gas_left.low_u64() * self.ext.schedule().wasm().opcodes_div as u64
						/ self.ext.schedule().wasm().opcodes_mul as u64;

				self.memory.set(result_ptr, &result)?;
				Ok(0i32.into())
			},
			vm::MessageCallResult::Reverted(gas_left, _) => {
				// cannot overflow, before making call gas_counter was incremented with gas, and gas_left < gas
				self.gas_counter = self.gas_counter -
					gas_left.low_u64() * self.ext.schedule().wasm().opcodes_div as u64
						/ self.ext.schedule().wasm().opcodes_mul as u64;

				self.memory.set(result_ptr, &result)?;
				Ok((-1i32).into())
			},
			vm::MessageCallResult::Failed  => {
				Ok((-1i32).into())
			}
		}
	}

	/// Message call
	fn ccall(&mut self, args: RuntimeArgs) -> Result<RuntimeValue> {
		self.do_call(true, CallType::Call, args)
	}

	/// Delegate call
	fn dcall(&mut self, args: RuntimeArgs) -> Result<RuntimeValue> {
		self.do_call(false, CallType::DelegateCall, args)
	}

	/// Static call
	fn scall(&mut self, args: RuntimeArgs) -> Result<RuntimeValue> {
		self.do_call(false, CallType::StaticCall, args)
	}

	fn return_address_ptr(&mut self, ptr: u32, val: Address) -> Result<()>
	{
		self.charge(|schedule| schedule.wasm().static_address as u64)?;
		self.memory.set(ptr, &*val)?;
		Ok(())
	}

	fn return_u256_ptr(&mut self, ptr: u32, val: U256) -> Result<()> {
		let value: H256 = val.into();
		self.charge(|schedule| schedule.wasm().static_u256 as u64)?;
		self.memory.set(ptr, &*value)?;
		Ok(())
	}

	/// Returns value (in Wei) passed to contract
	pub fn value(&mut self, args: RuntimeArgs) -> Result<()> {
		let val = self.context.value;
		self.return_u256_ptr(args.nth_checked(0)?, val)
	}

	/// Creates a new contract
	///
	/// Arguments:
	/// * endowment - how much value (in Wei) transfer to the newly created contract
	/// * code_ptr - pointer to the code data
	/// * code_len - lenght of the code data
	/// * result_ptr - pointer to write an address of the newly created contract
	pub fn create(&mut self, args: RuntimeArgs) -> Result<RuntimeValue>
	{
		//
		// method signature:
		//   fn create(endowment: *const u8, code_ptr: *const u8, code_len: u32, result_ptr: *mut u8) -> i32;
		//
		trace!(target: "wasm", "runtime: CREATE");
		let endowment = self.u256_at(args.nth_checked(0)?)?;
		trace!(target: "wasm", "       val: {:?}", endowment);
		let code_ptr: u32 = args.nth_checked(1)?;
		trace!(target: "wasm", "  code_ptr: {:?}", code_ptr);
		let code_len: u32 = args.nth_checked(2)?;
		trace!(target: "wasm", "  code_len: {:?}", code_len);
		let result_ptr: u32 = args.nth_checked(3)?;
		trace!(target: "wasm", "result_ptr: {:?}", result_ptr);

		let code = self.memory.get(code_ptr, code_len as usize)?;

		self.adjusted_charge(|schedule| schedule.create_gas as u64)?;
		self.adjusted_charge(|schedule| schedule.create_data_gas as u64 * code.len() as u64)?;

		let gas_left: U256 = U256::from(self.gas_left()?)
			* U256::from(self.ext.schedule().wasm().opcodes_mul)
			/ U256::from(self.ext.schedule().wasm().opcodes_div);

		match self.ext.create(&gas_left, &endowment, &code, vm::CreateContractAddress::FromSenderAndCodeHash) {
			vm::ContractCreateResult::Created(address, gas_left) => {
				self.memory.set(result_ptr, &*address)?;
				self.gas_counter = self.gas_limit -
					// this cannot overflow, since initial gas is in [0..u64::max) range,
					// and gas_left cannot be bigger
					gas_left.low_u64() * self.ext.schedule().wasm().opcodes_div as u64
						/ self.ext.schedule().wasm().opcodes_mul as u64;
				trace!(target: "wasm", "runtime: create contract success (@{:?})", address);
				Ok(0i32.into())
			},
			vm::ContractCreateResult::Failed => {
				trace!(target: "wasm", "runtime: create contract fail");
				Ok((-1i32).into())
			},
			vm::ContractCreateResult::Reverted(gas_left, _) => {
				trace!(target: "wasm", "runtime: create contract reverted");
				self.gas_counter = self.gas_limit -
					// this cannot overflow, since initial gas is in [0..u64::max) range,
					// and gas_left cannot be bigger
					gas_left.low_u64() * self.ext.schedule().wasm().opcodes_div as u64
						/ self.ext.schedule().wasm().opcodes_mul as u64;

				Ok((-1i32).into())
			},
		}
	}

	fn debug(&mut self, args: RuntimeArgs) -> Result<()>
	{
		let msg_ptr: u32 = args.nth_checked(0)?;
		let msg_len: u32 = args.nth_checked(1)?;
		let debug_str = String::from_utf8(
			self.memory.get(msg_ptr, msg_len as usize)?
		).map_err(|_| Error::BadUtf8)?;
		println!("Contract debug message: {}", debug_str);

		Ok(())
	}

	/// Pass suicide to state runtime
	pub fn suicide(&mut self, args: RuntimeArgs) -> Result<()>
	{
		let refund_address = self.address_at(args.nth_checked(0)?)?;

		if self.ext.exists(&refund_address).map_err(|_| Error::SuicideAbort)? {
			trace!(target: "wasm", "Suicide: refund to existing address {}", refund_address);
			self.adjusted_charge(|schedule| schedule.suicide_gas as u64)?;
		} else {
			trace!(target: "wasm", "Suicide: refund to new address {}", refund_address);
			self.adjusted_charge(|schedule| schedule.suicide_to_new_account_cost as u64)?;
		}

		self.ext.suicide(&refund_address).map_err(|_| Error::SuicideAbort)?;

		// We send trap to interpreter so it should abort further execution
		Err(Error::Suicide.into())
	}

	///	Signature: `fn blockhash(number: i64, dest: *mut u8)`
	pub fn blockhash(&mut self, args: RuntimeArgs) -> Result<()> {
		self.adjusted_charge(|schedule| schedule.blockhash_gas as u64)?;
		let hash = self.ext.blockhash(&U256::from(args.nth_checked::<u64>(0)?));
		self.memory.set(args.nth_checked(1)?, &*hash)?;

		Ok(())
	}

	///	Signature: `fn blocknumber() -> i64`
	pub fn blocknumber(&mut self) -> Result<RuntimeValue> {
		Ok(RuntimeValue::from(self.ext.env_info().number))
	}

	///	Signature: `fn coinbase(dest: *mut u8)`
	pub fn coinbase(&mut self, args: RuntimeArgs) -> Result<()> {
		let coinbase = self.ext.env_info().author;
		self.return_address_ptr(args.nth_checked(0)?, coinbase)
	}

	///	Signature: `fn difficulty(dest: *mut u8)`
	pub fn difficulty(&mut self, args: RuntimeArgs) -> Result<()> {
		let difficulty = self.ext.env_info().difficulty;
		self.return_u256_ptr(args.nth_checked(0)?, difficulty)
	}

	///	Signature: `fn gaslimit(dest: *mut u8)`
	pub fn gaslimit(&mut self, args: RuntimeArgs) -> Result<()> {
		let gas_limit = self.ext.env_info().gas_limit;
		self.return_u256_ptr(args.nth_checked(0)?, gas_limit)
	}

	///	Signature: `fn address(dest: *mut u8)`
	pub fn address(&mut self, args: RuntimeArgs) -> Result<()> {
		let address = self.context.address;
		self.return_address_ptr(args.nth_checked(0)?, address)
	}

	///	Signature: `sender(dest: *mut u8)`
	pub fn sender(&mut self, args: RuntimeArgs) -> Result<()> {
		let sender = self.context.sender;
		self.return_address_ptr(args.nth_checked(0)?, sender)
	}

	///	Signature: `origin(dest: *mut u8)`
	pub fn origin(&mut self, args: RuntimeArgs) -> Result<()> {
		let origin = self.context.origin;
		self.return_address_ptr(args.nth_checked(0)?, origin)
	}

	///	Signature: `timestamp() -> i64`
	pub fn timestamp(&mut self) -> Result<RuntimeValue> {
		let timestamp = self.ext.env_info().timestamp;
		Ok(RuntimeValue::from(timestamp))
	}

	///	Signature: `fn elog(topic_ptr: *const u8, topic_count: u32, data_ptr: *const u8, data_len: u32)`
	pub fn elog(&mut self, args: RuntimeArgs) -> Result<()>
	{
		let topic_ptr: u32 = args.nth_checked(0)?;
		let topic_count: u32 = args.nth_checked(1)?;
		let data_ptr: u32 = args.nth_checked(2)?;
		let data_len: u32 = args.nth_checked(3)?;

		if topic_count > 4 {
			return Err(Error::Log.into());
		}

		self.adjusted_overflow_charge(|schedule|
			{
				let topics_gas = schedule.log_gas as u64 + schedule.log_topic_gas as u64 * topic_count as u64;
				(schedule.log_data_gas as u64)
					.checked_mul(schedule.log_data_gas as u64)
					.and_then(|data_gas| data_gas.checked_add(topics_gas))
			}
		)?;

		let mut topics: Vec<H256> = Vec::with_capacity(topic_count as usize);
		topics.resize(topic_count as usize, H256::zero());
		for i in 0..topic_count {
			let offset = i.checked_mul(32).ok_or(Error::MemoryAccessViolation)?
				.checked_add(topic_ptr).ok_or(Error::MemoryAccessViolation)?;

			*topics.get_mut(i as usize)
				.expect("topics is resized to `topic_count`, i is in 0..topic count iterator, get_mut uses i as an indexer, get_mut cannot fail; qed")
				= H256::from(&self.memory.get(offset, 32)?[..]);
		}
		self.ext.log(topics, &self.memory.get(data_ptr, data_len as usize)?).map_err(|_| Error::Log)?;

		Ok(())
	}

	/// Signature: `fn get_bytes(key: *const u8, result: *mut u8)`
	pub fn get_bytes(&mut self, args: RuntimeArgs) -> Result<()> {
		let key = self.storage_bytes_key(self.h256_at(args.nth_checked(0)?)?);
		let bytes = self.ext.storage_bytes_at(&key).map_err(|_| Error::StorageReadError)?;
		self.memory.set(args.nth_checked(1)?, &bytes)?;
		Ok(())
	}

	/// Signature: `fn get_bytes_len(key: *const u8) -> u64`
	pub fn get_bytes_len(&mut self, args: RuntimeArgs) -> Result<RuntimeValue> {
		let key = self.storage_bytes_key(self.h256_at(args.nth_checked(0)?)?);
		let len = self.ext.storage_bytes_len(&key).map_err(|_| Error::StorageReadError)?;
		Ok(RuntimeValue::I64(len as i64))
	}

	/// Signature: `fn set_bytes(key: *const u8, bytes: *mut u8, len: u64)`
	pub fn set_bytes(&mut self, args: RuntimeArgs) -> Result<()> {
		let key = self.storage_bytes_key(self.h256_at(args.nth_checked(0)?)?);

		let former_bytes = self.ext.storage_bytes_at(&key).map_err(|_| Error::StorageUpdateError)?;

		let bytes_ptr: u32 = args.nth_checked(1)?;
		let len: u64 = args.nth_checked(2)?;
		let bytes = self.memory.get(bytes_ptr, len as usize)?;
		let is_bytes_empty = bytes.is_empty();

		let reset = !(former_bytes.is_empty() && !is_bytes_empty);
		self.storage_bytes_charge(len, reset)?;

		self.ext.set_storage_bytes(key, bytes).map_err(|_| Error::StorageUpdateError)?;

		if !former_bytes.is_empty() && is_bytes_empty {
			self.ext.inc_sstore_clears(former_bytes.len() as u64).map_err(|_| Error::StorageUpdateError)?;
		}

		Ok(())
	}

	/// Transform the key from the wasm input into the actual key stored in the
	/// underlying state trie.
	fn storage_bytes_key(&self, key: H256) -> H256 {
		hash::keccak(key)
	}
}

mod ext_impl {

	use wasmi::{Externals, RuntimeArgs, RuntimeValue, Trap};
	use env::ids::*;

	macro_rules! void {
		{ $e: expr } => { { $e?; Ok(None) } }
	}

	macro_rules! some {
		{ $e: expr } => { { Ok(Some($e?)) } }
	}

	macro_rules! cast {
		{ $e: expr } => { { Ok(Some($e)) } }
	}

	impl<'a> Externals for super::Runtime<'a> {
		fn invoke_index(
			&mut self,
			index: usize,
			args: RuntimeArgs,
		) -> Result<Option<RuntimeValue>, Trap> {
			match index {
				STORAGE_WRITE_FUNC => void!(self.storage_write(args)),
				STORAGE_READ_FUNC => void!(self.storage_read(args)),
				RET_FUNC => void!(self.ret(args)),
				GAS_FUNC => void!(self.gas(args)),
				INPUT_LENGTH_FUNC => cast!(self.input_legnth()),
				FETCH_INPUT_FUNC => void!(self.fetch_input(args)),
				PANIC_FUNC => void!(self.panic(args)),
				DEBUG_FUNC => void!(self.debug(args)),
				SYSCALL_FUNC => some!(self.syscall(args)),
				EXPF_FUNC => some!(self.expf(args)),
				CCALL_FUNC => some!(self.ccall(args)),
				DCALL_FUNC => some!(self.dcall(args)),
				SCALL_FUNC => some!(self.scall(args)),
				VALUE_FUNC => void!(self.value(args)),
				CREATE_FUNC => some!(self.create(args)),
				SUICIDE_FUNC => void!(self.suicide(args)),
				BLOCKHASH_FUNC => void!(self.blockhash(args)),
				BLOCKNUMBER_FUNC => some!(self.blocknumber()),
				COINBASE_FUNC => void!(self.coinbase(args)),
				DIFFICULTY_FUNC => void!(self.difficulty(args)),
				GASLIMIT_FUNC => void!(self.gaslimit(args)),
				TIMESTAMP_FUNC => some!(self.timestamp()),
				ADDRESS_FUNC => void!(self.address(args)),
				SENDER_FUNC => void!(self.sender(args)),
				ORIGIN_FUNC => void!(self.origin(args)),
				ELOG_FUNC => void!(self.elog(args)),
				GET_BYTES_FUNC => void!(self.get_bytes(args)),
				GET_BYTES_LEN_FUNC => some!(self.get_bytes_len(args)),
				SET_BYTES_FUNC => void!(self.set_bytes(args)),
				_ => panic!("env module doesn't provide function at index {}", index),
			}
		}
	}
}
