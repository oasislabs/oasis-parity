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
use std::io::Write;

use ethereum_types::{U256, H256, Address};
use hash;
use vm::{self, CallType};

use wasmer_runtime::{
	func,
	Ctx,
	memory::Memory,
	Value,
};

use super::panic_payload;

pub struct RuntimeContext {
	pub address: Address,
	pub sender: Address,
	pub origin: Address,
	pub value: U256,
}

pub struct Runtime<'a> {
	gas_counter: u64,
	gas_limit: u64,
	ext: &'a mut vm::Ext,
	context: RuntimeContext,
	memory: Memory,
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
		memory: Memory,
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

	fn memory_get_into(&self, ctx: &mut Ctx, offset: u32, mut buf: &mut [u8]) -> Result<()> {
		let mem_vec: Vec<u8> = ctx.memory(0).view()[offset as usize..(offset as usize + buf.len())]
			.iter()
			.map(|cell| cell.get())
			.collect();
		buf.write(mem_vec.as_slice());
		Ok(())
  }

	fn memory_get(&self, ctx: &mut Ctx, offset: u32, len: usize) -> Result<Vec<u8>> {
		let mem_get = ctx.memory(0).view()[offset as usize..(offset as usize + len)]
			.iter()
			.map(|cell| cell.get())
			.collect();
		Ok(mem_get)
  }

	fn memory_set(&mut self, ctx: &mut Ctx, offset: u32, buf: &[u8]) -> Result<()> {
		ctx.memory(0).view()[offset as usize..(offset as usize + buf.len())]
			.iter()
			.zip(buf.iter())
			.for_each(|(cell, v)| cell.set(*v));
		Ok(())
  }

	fn memory_zero(&mut self, ctx: &mut Ctx, offset: usize, len: usize) -> Result<()> {
		ctx.memory(0).view()[offset as usize..(offset as usize + len)]
			.iter()
			.for_each(|(cell)| cell.set(0u8));
		Ok(())
	}

	/// Loads 256-bit hash from the specifed sandboxed memory pointer
	fn h256_at(&self, ctx: &mut Ctx, ptr: u32) -> Result<H256> {
		let mut buf = [0u8; 32];
		self.memory_get_into(ctx, ptr, &mut buf[..])?;

		Ok(H256::from(&buf[..]))
	}

	/// Loads 160-bit hash (Ethereum address) from the specified sandboxed memory pointer
	fn address_at(&self, ctx: &mut Ctx, ptr: u32) -> Result<Address> {
		let mut buf = [0u8; 20];
		self.memory_get_into(ctx, ptr, &mut buf[..])?;

		Ok(Address::from(&buf[..]))
	}

	/// Loads 256-bit integer represented with bigendian from the specified sandboxed memory pointer
	fn u256_at(&self, ctx: &mut Ctx, ptr: u32) -> Result<U256> {
		let mut buf = [0u8; 32];
		self.memory_get_into(ctx, ptr, &mut buf[..])?;

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
	pub fn storage_read(&mut self, ctx: &mut Ctx, key_ptr: u32, val_ptr: u32) -> Result<()>
	{
		let key = self.h256_at(ctx, key_ptr)?;
		let val = self.ext.storage_at(&key).map_err(|_| Error::StorageReadError)?;

		self.adjusted_charge(|schedule| schedule.sload_gas as u64)?;

		self.memory_set(ctx, val_ptr as u32, &*val)?;

		Ok(())
	}

	/// Write to storage from wasm memory
	/// All storage written through here *must* be an H256.
	pub fn storage_write(&mut self, ctx: &mut Ctx, key_ptr: u32, val_ptr: u32) -> Result<()>
	{
		let key = self.h256_at(ctx, key_ptr)?;
		let val = self.h256_at(ctx, val_ptr)?;

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
	pub fn ret(&mut self, ctx: &mut Ctx, ptr: u32, len: u32) -> Result<()> {
		
		trace!(target: "wasm", "Contract ret: {} bytes @ {}", len, ptr);

		self.result = self.memory_get(ctx, ptr, len as usize)?;

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
	fn gas(&mut self, _ctx: &mut Ctx, amount: u32) -> Result<()> {
		if self.charge_gas(amount as u64) {
			Ok(())
		} else {
			Err(Error::GasLimit.into())
		}
	}

    /// Query the length of the input bytes
	fn input_length(&mut self, ctx: &mut Ctx) -> Result<i32> {
		Ok(self.args.len() as i32)
	}

	/// Write input bytes to the memory location using the passed pointer
	fn fetch_input(&mut self, ctx: &mut Ctx, ptr: u32) -> Result<()> {

		let args_len = self.args.len() as u64;
		self.charge(|s| args_len * s.wasm().memcpy as u64)?;

		self.memory_set(ctx, ptr, &self.args.clone()[..])?;
		Ok(())
	}

	/// Query the length of the return bytes
	fn return_length(&mut self, ctx: &mut Ctx) -> Result<i32> {
		Ok(self.result.len() as i32)
	}

	/// Write return bytes to the memory location using the passed pointer
	fn fetch_return(&mut self, ctx: &mut Ctx, ptr: u32) -> Result<()> {

		let return_length = self.result.len() as u64;
		self.charge(|s| return_length * s.wasm().memcpy as u64)?;

		self.memory_set(ctx, ptr, &self.result.clone()[..])?;
		Ok(())
	}

	/// User panic
	///
	/// Contract can invoke this when he encounters unrecoverable error.
	fn panic(&mut self, ctx: &mut Ctx, payload_ptr: u32, payload_len: u32) -> Result<()>
	{

		let raw_payload = self.memory_get(ctx, payload_ptr, payload_len as usize)?;
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
	fn syscall(&mut self, ctx: &mut Ctx, syscall_id: u32, data_ptr: u32) -> Result<i32>
	{
		
		Ok(match syscall_id {
			// https://github.com/rust-lang/rust/blob/master/src/etc/wasm32-shim.js
			1 => {
				let mem_bytes = self.memory_get(ctx, data_ptr, 4 * 3)?; // 3 words
				let payload = unsafe { mem::transmute::<Vec<u8>, Vec<u32>>(mem_bytes) };
				let out_str =
					String::from_utf8(self.memory_get(ctx, payload[1] as u32, payload[2] as usize)?)
						.map_err(|_| Error::BadUtf8)?;
				match payload.get(0) {
					Some(1) | Some(2) => {
						print!("{}", out_str);
						Ok(1)
					}
					Some(stream_id) => {
						Err(Error::Panic(format!("invalid output stream {}", stream_id)))
					}
					None => Err(Error::MemoryAccessViolation),
				}
			}
			2 => {
				let mem_bytes = self.memory_get(ctx, data_ptr, 4)?; // 1 word
				let payload = unsafe { mem::transmute::<Vec<u8>, Vec<u32>>(mem_bytes) };
				Err(Error::Panic(format!(
					"contract requested exit with code {}",
					payload.get(0).ok_or(Error::MemoryAccessViolation)?
				)))
			}
			3 => {
				// getargs(ret_buf_ptr: &mut u8, ret_buf_len: u32, args_len: &mut u32);
				// set the return buffer length to zero = no args
				self.memory_zero(ctx, data_ptr as usize + 4 * 2, 4)?;
				Ok(1)
			}
			4 => {
				// getenv(key_ptr: *const char, key_len: u32, val_ptr: &mut u8, ret_buf_len: mut u32, val_len: mut u32)
				// set val length to zero = no val
				self.memory_zero(ctx, data_ptr as usize + 4 * 4, 4)?;
				Ok(1)
			}
			6 => {
				// time(_: u32, high_s: mut u32, low_s: mut u32, subsec_nanos: mut u32);
				let ts_bytes = self.ext.env_info().timestamp.to_le_bytes();
				self.memory_set(ctx, data_ptr + 4 * 1, &ts_bytes[0..4])?;
				self.memory_set(ctx, data_ptr + 4 * 2, &ts_bytes[4..8])?;
				self.memory_zero(ctx, data_ptr as usize + 4 * 3, 4)?;
				Ok(1)
			}
			_ => Err(Error::Panic(format!(
				"Unimplemented syscall {}",
				syscall_id
			))),
		}?
		.into())
	}

	fn expf(&mut self, _ctx: &mut Ctx, x: f32) -> Result<f32> {
		Ok(x.exp())
	}

 	fn do_call(
		&mut self,
		ctx: &mut Ctx,
		use_val: bool,
		call_type: CallType,
		gas: u64,
		address_ptr: u32,
		val_ptr: u32,
		input_ptr: u32,
		input_len: u32,
		result_ptr: u32,
		result_alloc_len: u32
	) -> Result<i32>
	{
		trace!(target: "wasm", "runtime: CALL({:?})", call_type);

		trace!(target: "wasm", "           gas: {:?}", gas);

		let address = self.address_at(ctx, address_ptr)?;
		trace!(target: "wasm", "       address: {:?}", address);

		let vofs = if use_val { 1 } else { 0 };
		let val = if use_val { Some(self.u256_at(ctx, val_ptr)?) } else { None };
		trace!(target: "wasm", "           val: {:?}", val);

		trace!(target: "wasm", "     input_ptr: {:?}", input_ptr);
		trace!(target: "wasm", "     input_len: {:?}", input_len);
		trace!(target: "wasm", "    result_ptr: {:?}", result_ptr);
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
		let payload = self.memory_get(ctx, input_ptr, input_len as usize)?;

		let adjusted_gas = match gas.checked_mul(self.ext.schedule().wasm().opcodes_div as u64)
			.map(|x| x / self.ext.schedule().wasm().opcodes_mul as u64)
		{
			Some(x) => x,
			None => {
				trace!("CALL overflowed gas, call aborted with error returned");
				return Ok(-1)
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

				self.memory_set(ctx, result_ptr, &result)?;
				self.result = result;
				Ok(0)
			},
			vm::MessageCallResult::Reverted(gas_left, _) => {
				// cannot overflow, before making call gas_counter was incremented with gas, and gas_left < gas
				self.gas_counter = self.gas_counter -
					gas_left.low_u64() * self.ext.schedule().wasm().opcodes_div as u64
						/ self.ext.schedule().wasm().opcodes_mul as u64;

				self.memory_set(ctx, result_ptr, &result)?;
				Ok(-1)
			},
			vm::MessageCallResult::Failed  => {
				Ok(-1)
			}
		}
	}

	/// Message call
	pub fn ccall(&mut self, 
		ctx: &mut Ctx,
		gas: u64,
		address_ptr: u32,
		val_ptr: u32,
		input_ptr: u32,
		input_len: u32,
		result_ptr: u32,
		result_alloc_len: u32
	) -> Result<i32> {
		self.do_call(ctx, true, CallType::Call, gas, address_ptr, val_ptr, input_ptr, input_len, result_ptr, result_alloc_len)
	}

	/// Delegate call
	pub fn dcall(&mut self, 
		ctx: &mut Ctx,
		gas: u64,
		address_ptr: u32,
		input_ptr: u32,
		input_len: u32,
		result_ptr: u32,
		result_alloc_len: u32
	) -> Result<i32> {
		self.do_call(ctx, false, CallType::DelegateCall, gas, address_ptr, 0, input_ptr, input_len, result_ptr, result_alloc_len)
	}

	/// Static call
	pub fn scall(&mut self, 
		ctx: &mut Ctx,
		gas: u64,
		address_ptr: u32,
		input_ptr: u32,
		input_len: u32,
		result_ptr: u32,
		result_alloc_len: u32
	) -> Result<i32> {
		self.do_call(ctx, false, CallType::StaticCall, gas, address_ptr, 0, input_ptr, input_len, result_ptr, result_alloc_len)
	}

	fn return_address_ptr(&mut self, ctx: &mut Ctx, ptr: u32, val: Address) -> Result<()>
	{
		self.charge(|schedule| schedule.wasm().static_address as u64)?;
		self.memory_set(ctx, ptr, &*val)?;
		Ok(())
	}

	fn return_u256_ptr(&mut self, ctx: &mut Ctx, ptr: u32, val: U256) -> Result<()> {
		let value: H256 = val.into();
		self.charge(|schedule| schedule.wasm().static_u256 as u64)?;
		self.memory_set(ctx, ptr, &*value)?;
		Ok(())
	}

	/// Returns value (in Wei) passed to contract
	pub fn value(&mut self, ctx: &mut Ctx, ptr: u32) -> Result<()> {
		let val = self.context.value;
		self.return_u256_ptr(ctx, ptr, val)
	}

	/// Creates a new contract
	///
	/// Arguments:
	/// * endowment - how much value (in Wei) transfer to the newly created contract
	/// * code_ptr - pointer to the code data
	/// * code_len - lenght of the code data
	/// * result_ptr - pointer to write an address of the newly created contract
	pub fn create(&mut self, 
			ctx: &mut Ctx, 
			endowment_ptr: u32, 
			code_ptr: u32, 
			code_len: u32, 
			result_ptr: u32
		) -> Result<i32> 
	{
		//
		// method signature:
		//   fn create(endowment: *const u8, code_ptr: *const u8, code_len: u32, result_ptr: *mut u8) -> i32;
		//
 		trace!(target: "wasm", "runtime: CREATE");
		let endowment = self.u256_at(ctx, endowment_ptr)?;
/*		trace!(target: "wasm", "       val: {:?}", endowment);
		let code_ptr: u32 = args.nth_checked(1)?;
		trace!(target: "wasm", "  code_ptr: {:?}", code_ptr);
		let code_len: u32 = args.nth_checked(2)?;
		trace!(target: "wasm", "  code_len: {:?}", code_len);
		let result_ptr: u32 = args.nth_checked(3)?;
		trace!(target: "wasm", "result_ptr: {:?}", result_ptr);
 */
		let code = self.memory_get(ctx, code_ptr, code_len as usize)?;

		self.adjusted_charge(|schedule| schedule.create_gas as u64)?;
		self.adjusted_charge(|schedule| schedule.create_data_gas as u64 * code.len() as u64)?;

		let gas_left: U256 = U256::from(self.gas_left()?)
			* U256::from(self.ext.schedule().wasm().opcodes_mul)
			/ U256::from(self.ext.schedule().wasm().opcodes_div);

		match self.ext.create(&gas_left, &endowment, &code, vm::CreateContractAddress::FromSenderAndCodeHash) {
			vm::ContractCreateResult::Created(address, gas_left) => {
				self.memory_set(ctx, result_ptr, &*address)?;
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

	// This is the schema for runtime + Ctx support
	fn debug(&mut self, ctx: &mut Ctx, msg_ptr: u32, msg_len: u32) -> Result<()>
	{
		let debug_str = String::from_utf8(
			ctx.memory(0).view()[msg_ptr as usize..(msg_ptr + msg_len) as usize].iter().map(|cell| cell.get()).collect()
		).unwrap();
		Ok(())
	}

	/// Pass suicide to state runtime
	pub fn suicide(&mut self, ctx: &mut Ctx, ptr: u32) -> Result<()>
	{
		let refund_address = self.address_at(ctx, ptr)?;

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
	pub fn blockhash(&mut self, ctx: &mut Ctx, number: i64, dest_ptr: u32) -> Result<()> {
		self.adjusted_charge(|schedule| schedule.blockhash_gas as u64)?;
		let hash = self.ext.blockhash(&U256::from(number));
		self.memory_set(ctx, dest_ptr, &*hash)?;

		Ok(())
	}

	///	Signature: `fn blocknumber() -> i64`
	pub fn blocknumber(&mut self, _ctx: &mut Ctx,) -> Result<u64> {
		Ok(self.ext.env_info().number)
	}

	///	Signature: `fn coinbase(dest: *mut u8)`
	pub fn coinbase(&mut self, ctx: &mut Ctx, dest_ptr: u32) -> Result<()> {
		let coinbase = self.ext.env_info().author;
		self.return_address_ptr(ctx, dest_ptr, coinbase)
	}

	///	Signature: `fn difficulty(dest: *mut u8)`
	pub fn difficulty(&mut self, ctx: &mut Ctx, dest_ptr: u32) -> Result<()> {
		let difficulty = self.ext.env_info().difficulty;
		self.return_u256_ptr(ctx, dest_ptr, difficulty)
	}

	///	Signature: `fn gaslimit(dest: *mut u8)`
	pub fn gaslimit(&mut self, ctx: &mut Ctx, dest_ptr: u32) -> Result<()> {
		let gas_limit = self.ext.env_info().gas_limit;
		self.return_u256_ptr(ctx, dest_ptr, gas_limit)
	}

	///	Signature: `fn address(dest: *mut u8)`
	pub fn address(&mut self, ctx: &mut Ctx, addr_ptr: u32) -> Result<()> {
		let address = self.context.address;
		self.return_address_ptr(ctx, addr_ptr, address)
	}

	///	Signature: `sender(dest: *mut u8)`
	pub fn sender(&mut self, ctx: &mut Ctx, addr_ptr: u32) -> Result<()> {
		let sender = self.context.sender;
		self.return_address_ptr(ctx, addr_ptr, sender)
	}

	///	Signature: `origin(dest: *mut u8)`
	pub fn origin(&mut self, ctx: &mut Ctx, addr_ptr: u32) -> Result<()> {
		let origin = self.context.origin;
		self.return_address_ptr(ctx, addr_ptr, origin)
	}

	///	Signature: `timestamp() -> i64`
	pub fn timestamp(&mut self, _ctx: &mut Ctx) -> Result<u64> {
		let timestamp = self.ext.env_info().timestamp;
		Ok(timestamp)
	}

	///	Signature: `fn elog(topic_ptr: *const u8, topic_count: u32, data_ptr: *const u8, data_len: u32)`
	pub fn elog(&mut self, ctx: &mut Ctx, topic_ptr: u32, topic_count: u32, data_ptr: u32, data_len: u32) -> Result<()>
	{
		
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
				= H256::from(&self.memory_get(ctx, offset, 32)?[..]);
		}
		self.ext.log(topics, &self.memory_get(ctx, data_ptr, data_len as usize)?).map_err(|_| Error::Log)?;

		Ok(())
	}

	/// Signature: `fn get_bytes(key: *const u8, result: *mut u8)`
	pub fn get_bytes(&mut self, ctx: &mut Ctx, key_ptr: u32, result_ptr: u32) -> Result<()> {
		let key = self.storage_bytes_key(self.h256_at(ctx, key_ptr)?);
		let bytes = self.ext.storage_bytes_at(&key).map_err(|_| Error::StorageReadError)?;

		// Charge sload gas, scaled by number of bytes.
		let sload_gas = U256::from(self.schedule().sload_gas);
		let bytes_len = U256::from(bytes.len());

		// gas <- ceiling(sload_gas * bytes_len / 32)
		// Cannot overflow as gas and len are converted from u64s.
		let mut gas = sload_gas * bytes_len / U256::from(32);
		if sload_gas * bytes_len % U256::from(32) != U256::from(0) {
			gas = gas + U256::from(1);
		}

		// Charge gas after checking for u64 overflow.
		if gas > U256::from(std::u64::MAX) {
			return Err(Error::GasLimit);
		} else {
			self.adjusted_charge(|_| gas.as_u64())?;
		}

		self.memory_set(ctx, result_ptr, &bytes)?;
		Ok(())
	}

	/// Signature: `fn get_bytes_len(key: *const u8) -> u64`
	pub fn get_bytes_len(&mut self, ctx: &mut Ctx, key_ptr: u32) -> Result<i64> {
		let key = self.storage_bytes_key(self.h256_at(ctx, key_ptr)?);
		let len = self.ext.storage_bytes_len(&key).map_err(|_| Error::StorageReadError)?;
		Ok(len as i64)
	}

	/// Signature: `fn set_bytes(key: *const u8, bytes: *mut u8, len: u64)`
	pub fn set_bytes(&mut self, ctx: &mut Ctx, key_ptr: u32, bytes_ptr: u32, len: u64) -> Result<()> {
		let key = self.storage_bytes_key(self.h256_at(ctx, key_ptr)?);

		let former_bytes = self.ext.storage_bytes_at(&key).map_err(|_| Error::StorageUpdateError)?;

		let bytes = self.memory_get(ctx, bytes_ptr, len as usize)?;
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

pub mod imports {
	
	use std::ffi::c_void;
	use wasmer_runtime::{func, imports, Ctx, ImportObject};
  use super::{Memory, Result, Runtime};

	macro_rules! wrapped_imports {
		( $( $import_name:expr => $func:ident < [ $( $arg_name:ident : $arg_type:ident ),* ] -> [ $( $returns:ident ),* ] >, )* ) => {
				$(
						fn $func( ctx: &mut Ctx, $( $arg_name: $arg_type ),* ) -> Result<($( $returns ),*)> {
								let runtime: &mut Runtime = unsafe { &mut *(ctx.data as *mut Runtime) };
								runtime.$func(ctx, $( $arg_name, )* )
						}
				)*

				pub(crate) fn get_import_object(memory: Memory, raw_ptr: *mut c_void) -> wasmer_runtime::ImportObject {
						let dtor = (|_: *mut c_void| {}) as fn(*mut c_void);
						wasmer_runtime::imports! {
							move || { (raw_ptr, dtor) },
							"env" => {
									"memory" => memory,
									$(
											$import_name => func!($func),
									)*
							},
						}
				}
		}
	}

	wrapped_imports! {
		"create" => create<[endowment: u32, code_ptr: u32, code_len: u32, result_ptr: u32] -> [i32]>,
		"address" => address<[addr_ptr: u32] -> []>,
		"debug" => debug<[msg_ptr: u32, msg_len: u32] -> []>,
		"origin" => origin<[addr_ptr: u32] -> []>,
		"ret" => ret<[ptr: u32, len: u32] -> []>,
		"sender" => sender<[addr_ptr: u32] -> []>,
		"storage_read" => storage_read<[key_ptr: u32, val_ptr: u32] -> []>,
		"storage_write" => storage_write<[key_ptr: u32, val_ptr: u32] -> []>,
		"get_bytes" => get_bytes<[key_ptr: u32, result_ptr: u32] -> []>,
		"get_bytes_len" => get_bytes_len<[key_ptr: u32] -> [i64]>,
		"set_bytes" => set_bytes<[key_ptr: u32, bytes_ptr: u32, len: u64] -> []>,
		"value" => value<[ptr: u32] -> []>,
		"elog" => elog<[topic_ptr: u32, topic_count: u32, data_ptr: u32, data_len: u32] -> []>,
		"rust_wasm_syscall" => syscall<[syscall_id: u32, data_ptr: u32] -> [i32]>,
		"input_length" => input_length<[] -> [i32]>,
		"return_length" => return_length<[] -> [i32]>,
		"fetch_input" => fetch_input<[ptr: u32] -> []>,
		"fetch_return" => fetch_return<[ptr: u32] -> []>,
		"suicide" => suicide<[ptr: u32] -> []>,
		"blockhash" => blockhash<[number: i64, dest_ptr: u32] -> []>,
		"blocknumber" => blocknumber<[] -> [u64]>,
		"coinbase" => coinbase<[dest_ptr: u32] -> []>,
		"difficulty" => difficulty<[dest_ptr: u32] -> []>,
		"gaslimit" => gaslimit<[dest_ptr: u32] -> []>,
		"gas" => gas<[amount: u32] -> []>,
		"timestamp" => timestamp<[] -> [u64]>,
		"panic" => panic<[payload_ptr: u32, payload_len: u32] -> []>,
		"expf" => expf<[x: f32] -> [f32]>,
		"ccall" => ccall<[gas: u64, addr_ptr: u32, val_ptr: u32, input_ptr: u32, input_len: u32, result_ptr: u32, result_alloc_len: u32] -> [i32]>,
		"dcall" => dcall<[gas: u64, addr_ptr: u32, input_ptr: u32, input_len: u32, result_ptr: u32, result_alloc_len: u32] -> [i32]>,
		"scall" => scall<[gas: u64, addr_ptr: u32, input_ptr: u32, input_len: u32, result_ptr: u32, result_alloc_len: u32] -> [i32]>,
	}
}