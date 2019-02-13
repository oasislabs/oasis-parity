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

//! Transaction Execution environment.
use std::cmp;
use std::sync::Arc;
use hash::keccak;
use ethereum_types::{H256, U256, U512, Address};
use bytes::{Bytes, BytesRef};
use state::{Backend as StateBackend, State, Substate, CleanupMode};
use machine::EthereumMachine as Machine;
use error::ExecutionError;
use evm::{CallType, Finalize, FinalizationResult};
use vm::{
	self, Ext, EnvInfo, CreateContractAddress, ReturnData, CleanDustMode, ActionParams,
	ActionValue, Schedule, GasLeft, ContractHeader
};
use externalities::*;
use trace::{self, Tracer, VMTracer};
use trace_ext::{CountingTracer, ExtTracer, FullExtTracer, FullTracerCallTrace, FullTracerRecord, NoopExtTracer};
use transaction::{Action, SignedTransaction};
pub use executed::{Executed, ExecutionResult};
use confidential_vm::ConfidentialVm;

#[cfg(debug_assertions)]
/// Roughly estimate what stack size each level of evm depth will use. (Debug build)
const STACK_SIZE_PER_DEPTH: usize = 1024 * 1024;

#[cfg(not(debug_assertions))]
/// Roughly estimate what stack size each level of evm depth will use.
const STACK_SIZE_PER_DEPTH: usize = 1024 * 1024;

#[cfg(debug_assertions)]
/// Entry stack overhead prior to execution. (Debug build)
const STACK_SIZE_ENTRY_OVERHEAD: usize = 100 * 1024;

#[cfg(not(debug_assertions))]
/// Entry stack overhead prior to execution.
const STACK_SIZE_ENTRY_OVERHEAD: usize = 20 * 1024;

/// Returns new address created from address, nonce, and code hash
pub fn contract_address(address_scheme: CreateContractAddress, sender: &Address, nonce: &U256, code: &[u8]) -> (Address, Option<H256>) {
	use rlp::RlpStream;

	match address_scheme {
		CreateContractAddress::FromSenderAndNonce => {
			let mut stream = RlpStream::new_list(2);
			stream.append(sender);
			stream.append(nonce);
			(From::from(keccak(stream.as_raw())), None)
		},
		CreateContractAddress::FromCodeHash => {
			let code_hash = keccak(code);
			let mut buffer = [0xffu8; 20 + 32];
			&mut buffer[20..].copy_from_slice(&code_hash[..]);
			(From::from(keccak(&buffer[..])), Some(code_hash))
		},
		CreateContractAddress::FromSenderAndCodeHash => {
			let code_hash = keccak(code);
			let mut buffer = [0u8; 20 + 32];
			&mut buffer[..20].copy_from_slice(&sender[..]);
			&mut buffer[20..].copy_from_slice(&code_hash[..]);
			(From::from(keccak(&buffer[..])), Some(code_hash))
		},
	}
}

/// Transaction execution options.
#[derive(Clone)]
pub struct TransactOptions<T, V, X> {
	/// Enable call tracing.
	pub tracer: T,
	/// Enable VM tracing.
	pub vm_tracer: V,
	/// Enable Externalties tracing.
	pub ext_tracer: X,
	/// Check transaction nonce before execution.
	pub check_nonce: bool,
	/// Records the output from init contract calls.
	pub output_from_init_contract: bool,
}

impl<T, V, X> PartialEq for TransactOptions<T, V, X> where T: PartialEq, V: PartialEq, X: PartialEq {
	fn eq(&self, other: &TransactOptions<T, V, X>) -> bool {
		self.tracer == other.tracer
			&& self.vm_tracer == other.vm_tracer
			&& self.ext_tracer == other.ext_tracer
			&& self.check_nonce == other.check_nonce
			&& self.output_from_init_contract == other.output_from_init_contract
	}
}

impl<T, V, X> TransactOptions<T, V, X> {
	/// Create new `TransactOptions` with given tracer and VM tracer.
	pub fn new(tracer: T, vm_tracer: V, ext_tracer: X) -> Self {
		TransactOptions {
			tracer,
			vm_tracer,
			ext_tracer,
			check_nonce: true,
			output_from_init_contract: false,
		}
	}

	/// Disables the nonce check
	pub fn dont_check_nonce(mut self) -> Self {
		self.check_nonce = false;
		self
	}

	/// Saves the output from contract creation.
	pub fn save_output_from_contract(mut self) -> Self {
		self.output_from_init_contract = true;
		self
	}
}

impl TransactOptions<trace::ExecutiveTracer, trace::ExecutiveVMTracer, NoopExtTracer> {
	/// Creates new `TransactOptions` with default tracing and VM tracing.
	pub fn with_tracing_and_vm_tracing() -> Self {
		TransactOptions {
			tracer: trace::ExecutiveTracer::default(),
			vm_tracer: trace::ExecutiveVMTracer::toplevel(),
			ext_tracer: NoopExtTracer,
			check_nonce: true,
			output_from_init_contract: false,
		}
	}
}

impl TransactOptions<trace::ExecutiveTracer, trace::NoopVMTracer, NoopExtTracer> {
	/// Creates new `TransactOptions` with default tracing and no VM tracing.
	pub fn with_tracing() -> Self {
		TransactOptions {
			tracer: trace::ExecutiveTracer::default(),
			vm_tracer: trace::NoopVMTracer,
			ext_tracer: NoopExtTracer,
			check_nonce: true,
			output_from_init_contract: false,
		}
	}
}

impl TransactOptions<trace::NoopTracer, trace::ExecutiveVMTracer, NoopExtTracer> {
	/// Creates new `TransactOptions` with no tracing and default VM tracing.
	pub fn with_vm_tracing() -> Self {
		TransactOptions {
			tracer: trace::NoopTracer,
			vm_tracer: trace::ExecutiveVMTracer::toplevel(),
			ext_tracer: NoopExtTracer,
			check_nonce: true,
			output_from_init_contract: false,
		}
	}
}

impl TransactOptions<trace::NoopTracer, trace::NoopVMTracer, NoopExtTracer> {
	/// Creates new `TransactOptions` without any tracing.
	pub fn with_no_tracing() -> Self {
		TransactOptions {
			tracer: trace::NoopTracer,
			vm_tracer: trace::NoopVMTracer,
			ext_tracer: NoopExtTracer,
			check_nonce: true,
			output_from_init_contract: false,
		}
	}
}

/// Transaction executor.
pub struct Executive<'a, B: 'a + StateBackend> {
	state: &'a mut State<B>,
	info: &'a EnvInfo,
	machine: &'a Machine,
	depth: usize,
	static_flag: bool
}

impl<'a, B: 'a + StateBackend> Executive<'a, B> {
	/// Basic constructor.
	pub fn new(state: &'a mut State<B>, info: &'a EnvInfo, machine: &'a Machine) -> Self {
		Executive {
			state: state,
			info: info,
			machine: machine,
			depth: 0,
			static_flag: false,
		}
	}

	/// Populates executive from parent properties. Increments executive depth.
	pub fn from_parent(state: &'a mut State<B>, info: &'a EnvInfo, machine: &'a Machine, parent_depth: usize, static_flag: bool) -> Self {
		Executive {
			state: state,
			info: info,
			machine: machine,
			depth: parent_depth + 1,
			static_flag: static_flag,
		}
	}

	/// Creates `Externalities` from `Executive`.
	pub fn as_externalities<'any, T, V, X>(
		&'any mut self,
		origin_info: OriginInfo,
		substate: &'any mut Substate,
		output: OutputPolicy<'any, 'any>,
		tracer: &'any mut T,
		vm_tracer: &'any mut V,
		ext_tracer: &'any mut X,
		static_call: bool,
	) -> Externalities<'any, T, V, X, B> where T: Tracer, V: VMTracer, X: ExtTracer {
		let is_static = self.static_flag || static_call;
		Externalities::new(self.state, self.info, self.machine, self.depth, origin_info, substate, output, tracer, vm_tracer, ext_tracer, is_static)
	}

	/// This function should be used to execute transaction.
	pub fn transact<T, V, X>(&'a mut self, t: &SignedTransaction, options: TransactOptions<T, V, X>)
		-> Result<Executed<T::Output, V::Output>, ExecutionError> where T: Tracer, V: VMTracer, X: ExtTracer,
	{
		self.transact_with_tracer(t, options.check_nonce, options.output_from_init_contract, options.tracer, options.vm_tracer, options.ext_tracer)
	}

	/// Execute a transaction in a "virtual" context.
	/// This will ensure the caller has enough balance to execute the desired transaction.
	/// Used for extra-block executions for things like consensus contracts and RPCs
	pub fn transact_virtual<T, V, X>(&'a mut self, t: &SignedTransaction, options: TransactOptions<T, V, X>)
		-> Result<Executed<T::Output, V::Output>, ExecutionError> where T: Tracer, V: VMTracer, X: ExtTracer,
	{
		let sender = t.sender();
		let balance = self.state.balance(&sender)?;
		let needed_balance = t.value.saturating_add(t.gas.saturating_mul(t.gas_price));
		if balance < needed_balance {
			// give the sender a sufficient balance
			self.state.add_balance(&sender, &(needed_balance - balance), CleanupMode::NoEmpty)?;
		}

		self.transact(t, options)
	}

	/// Execute transaction/call with tracing enabled
	fn transact_with_tracer<T, V, X>(
		&'a mut self,
		t: &SignedTransaction,
		check_nonce: bool,
		output_from_create: bool,
		mut tracer: T,
		mut vm_tracer: V,
		mut ext_tracer: X
	) -> Result<Executed<T::Output, V::Output>, ExecutionError> where T: Tracer, V: VMTracer, X: ExtTracer {
		let sender = t.sender();
		let nonce = self.state.nonce(&sender)?;

		// extract deployment header from code
		let header = self.state.extract_header(t)
					   .map_err(|e| ExecutionError::TransactionMalformed(e))?;

		let schedule = self.machine.schedule(self.info.number);
		let confidential = header.as_ref().map_or(false, |h| h.confidential);
		let base_gas_required = U256::from(t.gas_required(&schedule, confidential));

		if t.gas < base_gas_required {
			return Err(ExecutionError::NotEnoughBaseGas { required: base_gas_required, got: t.gas });
		}

		if !t.is_unsigned() && check_nonce && schedule.kill_dust != CleanDustMode::Off && !self.state.exists(&sender)? {
			return Err(ExecutionError::SenderMustExist);
		}

		let init_gas = t.gas - base_gas_required;

		// validate transaction nonce
		if check_nonce && t.nonce != nonce {
			return Err(ExecutionError::InvalidNonce { expected: nonce, got: t.nonce });
		}

		// validate if transaction fits into given block
		if self.info.gas_used + t.gas > self.info.gas_limit {
			return Err(ExecutionError::BlockGasLimitReached {
				gas_limit: self.info.gas_limit,
				gas_used: self.info.gas_used,
				gas: t.gas
			});
		}

		// TODO: we might need bigints here, or at least check overflows.
		let balance = self.state.balance(&sender)?;
		let gas_cost = t.gas.full_mul(t.gas_price);
		let total_cost = U512::from(t.value) + gas_cost;

		// avoid unaffordable transactions
		let balance512 = U512::from(balance);
		if balance512 < total_cost {
			return Err(ExecutionError::NotEnoughCash { required: total_cost, got: balance512 });
		}

		let mut substate = Substate::new();

		// NOTE: there can be no invalid transactions from this point.
		if !schedule.eip86 || !t.is_unsigned() {
			self.state.inc_nonce(&sender)?;
		}
		self.state.sub_balance(&sender, &U256::from(gas_cost), &mut substate.to_cleanup_mode(&schedule))?;

		let (result, output) = match t.action {
			Action::Create => {
				let (new_address, code_hash) = contract_address(self.machine.create_address_scheme(self.info.number), &sender, &nonce, &t.data);
				let params = ActionParams {
					code_address: new_address.clone(),
					code_hash: code_hash,
					address: new_address,
					sender: sender.clone(),
					origin: sender.clone(),
					gas: init_gas,
					gas_price: t.gas_price,
					value: ActionValue::Transfer(t.value),
					// strip contract header (if present)
					code: Some(header.as_ref().map_or(Arc::new(t.data.clone()), |h| h.code.clone())),
					data: None,
					call_type: CallType::None,
					params_type: vm::ParamsType::Embedded,
					confidential: confidential,
					header: header,
				};
				let mut out = if output_from_create { Some(vec![]) } else { None };
				(self.create(params, &mut substate, &mut out, &mut tracer, &mut vm_tracer, &mut ext_tracer), out.unwrap_or_else(Vec::new))
			},
			Action::Call(ref address) => {
				let params = ActionParams {
					code_address: address.clone(),
					address: address.clone(),
					sender: sender.clone(),
					origin: sender.clone(),
					gas: init_gas,
					gas_price: t.gas_price,
					value: ActionValue::Transfer(t.value),
					// strip contract header (if present)
					code: header.as_ref().map_or(self.state.code(address)?, |h| Some(h.code.clone())),
					code_hash: Some(self.state.code_hash(address)?),
					data: Some(t.data.clone()),
					call_type: CallType::Call,
					params_type: vm::ParamsType::Separate,
					confidential: confidential,
					header: header,
				};
				let mut out = vec![];
				(self.call(params, &mut substate, BytesRef::Flexible(&mut out), &mut tracer, &mut vm_tracer, &mut ext_tracer), out)
			}
		};

		// finalize here!
		Ok(self.finalize(t, substate, result, output, tracer.drain(), vm_tracer.drain())?)
	}

	fn exec_vm<T, V, X>(
		&mut self,
		schedule: Schedule,
		params: ActionParams,
		unconfirmed_substate: &mut Substate,
		output_policy: OutputPolicy,
		tracer: &mut T,
		vm_tracer: &mut V,
		ext_tracer: &mut X,
	) -> vm::Result<FinalizationResult> where T: Tracer, V: VMTracer, X: ExtTracer {
		let local_stack_size = ::std::usize::MAX;
		let depth_threshold = local_stack_size.saturating_sub(STACK_SIZE_ENTRY_OVERHEAD) / STACK_SIZE_PER_DEPTH;
		let static_call = params.call_type == CallType::StaticCall;

		// if this is a create with a header, save the raw header bytes to prepend to the bytecode
		let raw_header = if params.call_type == CallType::None {
			params.header.as_ref().map(|h| h.raw_header.clone())
		}
		else {
			None
		};

		let vm_factory = self.state.vm_factory();
		let mut ext = self.as_externalities(OriginInfo::from(&params), unconfirmed_substate, output_policy, tracer, vm_tracer, ext_tracer, static_call);
		trace!(target: "executive", "ext.schedule.have_delegate_call: {}", ext.schedule().have_delegate_call);
		let mut vm = vm_factory.create(&params, &schedule);
		let ret = vm.exec(params, &mut ext);

		// prepend header to the bytecode that is stored in the account
		if let Some(bytes) = raw_header {
			if let Ok(GasLeft::NeedsReturn { gas_left, data, apply_state }) = ret {
				let mut bytecode = bytes;
				bytecode.append(&mut data.to_vec());
				let size = bytecode.len();
				return Ok(GasLeft::NeedsReturn {
					gas_left,
					data: ReturnData::new(bytecode, 0, size),
					apply_state
				}).finalize(ext);
			}
		}

		ret.finalize(ext)
	}

	/// Calls contract function with given contract params.
	/// NOTE. It does not finalize the transaction (doesn't do refunds, nor suicides).
	/// Modifies the substate and the output.
	/// Returns either gas_left or `vm::Error`.
	pub fn call<T, V, X>(
		&mut self,
		params: ActionParams,
		substate: &mut Substate,
		mut output: BytesRef,
		tracer: &mut T,
		vm_tracer: &mut V,
		ext_tracer: &mut X
	) -> vm::Result<FinalizationResult> where T: Tracer, V: VMTracer, X: ExtTracer {

		trace!("Executive::call(params={:?}) self.env_info={:?}, static={}", params, self.info, self.static_flag);
		if (params.call_type == CallType::StaticCall ||
				((params.call_type == CallType::Call) &&
				self.static_flag))
			&& params.value.value() > 0.into() {
			return Err(vm::Error::MutableCallInStaticContext);
		}

		// Fail immediately if this is a call to an expired contract.
		if let Some(ref code) = params.code {
			if code.len() > 0 && self.info.timestamp > self.state.storage_expiry(&params.code_address)? {
				let trace_info = tracer.prepare_trace_call(&params);
				tracer.trace_failed_call(trace_info, vec![], vm::Error::Reverted.into());
				return Err(vm::Error::Reverted);
			}
		}

		// backup used in case of running out of gas
		self.state.checkpoint();

		let schedule = self.machine.schedule(self.info.number);

		// at first, transfer value to destination
		if let ActionValue::Transfer(val) = params.value {
			self.state.transfer_balance(&params.sender, &params.address, &val, substate.to_cleanup_mode(&schedule))?;
		}

		// if destination is builtin, try to execute it
		if let Some(builtin) = self.machine.builtin(&params.code_address, self.info.number) {
			// Engines aren't supposed to return builtins until activation, but
			// prefer to fail rather than silently break consensus.
			if !builtin.is_active(self.info.number) {
				panic!("Consensus failure: engine implementation prematurely enabled built-in at {}", params.code_address);
			}

			let default = [];
			let data = if let Some(ref d) = params.data { d as &[u8] } else { &default as &[u8] };

			let trace_info = tracer.prepare_trace_call(&params);

			let cost = builtin.cost(data);
			if cost <= params.gas {
				let mut builtin_out_buffer = Vec::new();
				let result = {
					let mut builtin_output = BytesRef::Flexible(&mut builtin_out_buffer);
					builtin.execute(data, &mut builtin_output)
				};
				if let Err(e) = result {
					self.state.revert_to_checkpoint();
					let evm_err: vm::Error = e.into();
					tracer.trace_failed_call(trace_info, vec![], evm_err.clone().into());
					Err(evm_err)
				} else {
					self.state.discard_checkpoint();
					output.write(0, &builtin_out_buffer);

					// Trace only top level calls and calls with balance transfer to builtins. The reason why we don't
					// trace all internal calls to builtin contracts is that memcpy (IDENTITY) is a heavily used
					// function.
					let is_transferred = match params.value {
						ActionValue::Transfer(value) => value != U256::zero(),
						ActionValue::Apparent(_) => false,
					};
					if self.depth == 0 || is_transferred {
						let mut trace_output = tracer.prepare_trace_output();
						if let Some(out) = trace_output.as_mut() {
							*out = output.to_owned();
						}

						tracer.trace_call(
							trace_info,
							cost,
							trace_output,
							vec![]
						);
					}

					let out_len = builtin_out_buffer.len();
					Ok(FinalizationResult {
						gas_left: params.gas - cost,
						return_data: ReturnData::new(builtin_out_buffer, 0, out_len),
						apply_state: true,
					})
				}
			} else {
				// just drain the whole gas
				self.state.revert_to_checkpoint();

				tracer.trace_failed_call(trace_info, vec![], vm::Error::OutOfGas.into());

				Err(vm::Error::OutOfGas)
			}
		} else {
			let trace_info = tracer.prepare_trace_call(&params);
			let mut trace_output = tracer.prepare_trace_output();
			let mut subtracer = tracer.subtracer();

			let gas = params.gas;

			if params.code.is_some() {
				// part of substate that may be reverted
				let mut unconfirmed_substate = Substate::new();

				// TODO: make ActionParams pass by ref then avoid copy altogether.
				let mut subvmtracer = vm_tracer.prepare_subtrace(params.code.as_ref().expect("scope is conditional on params.code.is_some(); qed"));

				let mut subexttracer = ext_tracer.subtracer(&params.address);
				let res = {
					self.exec_vm(schedule, params, &mut unconfirmed_substate, OutputPolicy::Return(output, trace_output.as_mut()), &mut subtracer, &mut subvmtracer, &mut subexttracer)
				};

				vm_tracer.done_subtrace(subvmtracer);

				trace!(target: "executive", "res={:?}", res);

				let traces = subtracer.drain();
				match res {
					Ok(ref res) if res.apply_state => tracer.trace_call(
						trace_info,
						gas - res.gas_left,
						trace_output,
						traces
					),
					Ok(_) => tracer.trace_failed_call(trace_info, traces, vm::Error::Reverted.into()),
					Err(ref e) => tracer.trace_failed_call(trace_info, traces, e.into()),
				};

				trace!(target: "executive", "substate={:?}; unconfirmed_substate={:?}\n", substate, unconfirmed_substate);

				self.enact_result(&res, substate, unconfirmed_substate);
				trace!(target: "executive", "enacted: substate={:?}\n", substate);
				res
			} else {
				// otherwise it's just a basic transaction, only do tracing, if necessary.
				self.state.discard_checkpoint();

				tracer.trace_call(trace_info, U256::zero(), trace_output, vec![]);
				Ok(FinalizationResult {
					gas_left: params.gas,
					return_data: ReturnData::empty(),
					apply_state: true,
				})
			}
		}
	}

	/// Creates contract with given contract params.
	/// NOTE. It does not finalize the transaction (doesn't do refunds, nor suicides).
	/// Modifies the substate.
	pub fn create<T, V, X>(
		&mut self,
		params: ActionParams,
		substate: &mut Substate,
		output: &mut Option<Bytes>,
		tracer: &mut T,
		vm_tracer: &mut V,
		ext_tracer: &mut X,
	) -> vm::Result<FinalizationResult> where T: Tracer, V: VMTracer, X: ExtTracer {

		// EIP-684: If a contract creation is attempted, due to either a creation transaction or the
		// CREATE (or future CREATE2) opcode, and the destination address already has either
		// nonzero nonce, or nonempty code, then the creation throws immediately, with exactly
		// the same behavior as would arise if the first byte in the init code were an invalid
		// opcode. This applies retroactively starting from genesis.
		if self.state.exists_and_has_code_or_nonce(&params.address)? {
			return Err(vm::Error::OutOfGas);
		}

		trace!("Executive::create(params={:?}) self.env_info={:?}, static={}", params, self.info, self.static_flag);
		if params.call_type == CallType::StaticCall || self.static_flag {
			let trace_info = tracer.prepare_trace_create(&params);
			tracer.trace_failed_create(trace_info, vec![], vm::Error::MutableCallInStaticContext.into());
			return Err(vm::Error::MutableCallInStaticContext);
		}

		// backup used in case of running out of gas
		self.state.checkpoint();

		// part of substate that may be reverted
		let mut unconfirmed_substate = Substate::new();

		let schedule = self.machine.schedule(self.info.number);

		// storage expiry
		let storage_expiry = params.header.as_ref().map(|h| h.expiry).and_then(Into::into)
			.unwrap_or(self.info.timestamp + schedule.default_storage_duration);

		// fail if expiry has passed
		if self.info.timestamp > storage_expiry {
			let trace_info = tracer.prepare_trace_create(&params);
			tracer.trace_failed_create(trace_info, vec![], vm::Error::Reverted.into());
			return Err(vm::Error::Reverted);
		}

		// create contract and transfer value to it if necessary
		let nonce_offset = if schedule.no_empty {1} else {0}.into();
		let prev_bal = self.state.balance(&params.address)?;
		if let ActionValue::Transfer(val) = params.value {
			self.state.sub_balance(&params.sender, &val, &mut substate.to_cleanup_mode(&schedule))?;
			self.state.new_contract(&params.address, val + prev_bal, nonce_offset, storage_expiry);
		} else {
			self.state.new_contract(&params.address, prev_bal, nonce_offset, storage_expiry);
		}

		let trace_info = tracer.prepare_trace_create(&params);
		let mut trace_output = tracer.prepare_trace_output();
		let mut subtracer = tracer.subtracer();
		let gas = params.gas;
		let created = params.address.clone();

		let mut subvmtracer = vm_tracer.prepare_subtrace(params.code.as_ref().expect("two ways into create (Externalities::create and Executive::transact_with_tracer); both place `Some(...)` `code` in `params`; qed"));

		let mut subexttracer = ext_tracer.subtracer(&params.address);
		let res = self.exec_vm(
			schedule,
			params,
			&mut unconfirmed_substate,
			OutputPolicy::InitContract(output.as_mut().or(trace_output.as_mut())),
			&mut subtracer,
			&mut subvmtracer,
			&mut subexttracer
		);

		vm_tracer.done_subtrace(subvmtracer);

		match res {
			Ok(ref res) if res.apply_state => tracer.trace_create(
				trace_info,
				gas - res.gas_left,
				trace_output.map(|data| output.as_ref().map(|out| out.to_vec()).unwrap_or(data)),
				created,
				subtracer.drain()
			),
			Ok(_) => tracer.trace_failed_create(trace_info, subtracer.drain(), vm::Error::Reverted.into()),
			Err(ref e) => tracer.trace_failed_create(trace_info, subtracer.drain(), e.into())
		};

		self.enact_result(&res, substate, unconfirmed_substate);
		res
	}

	/// Finalizes the transaction (does refunds and suicides).
	fn finalize<T, V>(
		&mut self,
		t: &SignedTransaction,
		mut substate: Substate,
		result: vm::Result<FinalizationResult>,
		output: Bytes,
		trace: Vec<T>,
		vm_trace: Option<V>
	) -> Result<Executed<T, V>, ExecutionError> {
		let schedule = self.machine.schedule(self.info.number);

		// refunds from SSTORE nonzero -> zero
		let sstore_refunds = substate.sstore_clears_refund;
		// refunds from contract suicides
		let suicide_refunds = U256::from(schedule.suicide_refund_gas) * U256::from(substate.suicides.len());
		let refunds_bound = sstore_refunds + suicide_refunds;

		// real ammount to refund
		let gas_left_prerefund = match result { Ok(FinalizationResult{ gas_left, .. }) => gas_left, _ => 0.into() };
		let refunded = cmp::min(refunds_bound, (t.gas - gas_left_prerefund) >> 1);
		let gas_left = gas_left_prerefund + refunded;

		let gas_used = t.gas - gas_left;
		let refund_value = gas_left * t.gas_price;
		let fees_value = gas_used * t.gas_price;

		trace!("exec::finalize: t.gas={}, sstore_refunds={}, suicide_refunds={}, refunds_bound={}, gas_left_prerefund={}, refunded={}, gas_left={}, gas_used={}, refund_value={}, fees_value={}\n",
			t.gas, sstore_refunds, suicide_refunds, refunds_bound, gas_left_prerefund, refunded, gas_left, gas_used, refund_value, fees_value);

		let sender = t.sender();
		trace!("exec::finalize: Refunding refund_value={}, sender={}\n", refund_value, sender);
		// Below: NoEmpty is safe since the sender must already be non-null to have sent this transaction
		self.state.add_balance(&sender, &refund_value, CleanupMode::NoEmpty)?;
		trace!("exec::finalize: Compensating author: fees_value={}, author={}\n", fees_value, &self.info.author);
		self.state.add_balance(&self.info.author, &fees_value, substate.to_cleanup_mode(&schedule))?;

		// perform suicides
		for address in &substate.suicides {
			self.state.kill_account(address);
		}

		// perform garbage-collection
		let min_balance = if schedule.kill_dust != CleanDustMode::Off { Some(U256::from(schedule.tx_gas) * t.gas_price) } else { None };
		self.state.kill_garbage(&substate.touched, schedule.kill_empty, &min_balance, schedule.kill_dust == CleanDustMode::WithCodeAndStorage)?;

		match result {
			Err(vm::Error::Internal(msg)) => Err(ExecutionError::Internal(msg)),
			Err(exception) => {
				trace!("Executive::finalize: exception={}", exception);
				Ok(Executed {
					exception: Some(exception),
					gas: t.gas,
					gas_used: t.gas,
					refunded: U256::zero(),
					cumulative_gas_used: self.info.gas_used + t.gas,
					logs: vec![],
					contracts_created: vec![],
					output: output,
					trace: trace,
					vm_trace: vm_trace,
					state_diff: None,
				})
			},
			Ok(r) => {
				Ok(Executed {
					exception: if r.apply_state { None } else { Some(vm::Error::Reverted) },
					gas: t.gas,
					gas_used: gas_used,
					refunded: refunded,
					cumulative_gas_used: self.info.gas_used + gas_used,
					logs: substate.logs,
					contracts_created: substate.contracts_created,
					output: output,
					trace: trace,
					vm_trace: vm_trace,
					state_diff: None,
				})
			},
		}
	}

	fn enact_result(&mut self, result: &vm::Result<FinalizationResult>, substate: &mut Substate, un_substate: Substate) {
		match *result {
			Err(vm::Error::OutOfGas)
				| Err(vm::Error::BadJumpDestination {..})
				| Err(vm::Error::BadInstruction {.. })
				| Err(vm::Error::StackUnderflow {..})
				| Err(vm::Error::BuiltIn {..})
				| Err(vm::Error::Wasm {..})
				| Err(vm::Error::OutOfStack {..})
				| Err(vm::Error::MutableCallInStaticContext)
				| Err(vm::Error::OutOfBounds)
				| Err(vm::Error::Reverted)
				| Ok(FinalizationResult { apply_state: false, .. }) => {
					self.state.revert_to_checkpoint();
			},
			Ok(_) | Err(vm::Error::Internal(_)) => {
				self.state.discard_checkpoint();
				substate.accrue(un_substate);
			}
		}
	}
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
	use std::sync::Arc;
	use std::str::FromStr;
	use rustc_hex::FromHex;
	use ethkey::{Generator, Random};
	use super::*;
	use ethereum_types::{H256, U256, U512, Address};
	use bytes::BytesRef;
	use vm::{ActionParams, ActionValue, CallType, EnvInfo, CreateContractAddress};
	use evm::{Factory, VMType};
	use error::ExecutionError;
	use machine::EthereumMachine;
	use state::{Substate, CleanupMode};
	use test_helpers::{get_temp_state_with_factory, get_temp_state};
	use trace::trace;
	use trace::{FlatTrace, Tracer, NoopTracer, ExecutiveTracer};
	use trace::{VMTrace, VMOperation, VMExecutedOperation, MemoryDiff, StorageDiff, VMTracer, NoopVMTracer, ExecutiveVMTracer};
	use transaction::{Action, Transaction};

	fn make_frontier_machine(max_depth: usize) -> EthereumMachine {
		let mut machine = ::ethereum::new_frontier_test_machine();
		machine.set_schedule_creation_rules(Box::new(move |s, _| s.max_depth = max_depth));
		machine
	}

	fn make_byzantium_machine(max_depth: usize) -> EthereumMachine {
		let mut machine = ::ethereum::new_byzantium_test_machine();
		machine.set_schedule_creation_rules(Box::new(move |s, _| s.max_depth = max_depth));
		machine
	}

	#[test]
	fn test_contract_address() {
		let address = Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
		let expected_address = Address::from_str("3f09c73a5ed19289fb9bdc72f1742566df146f56").unwrap();
		assert_eq!(expected_address, contract_address(CreateContractAddress::FromSenderAndNonce, &address, &U256::from(88), &[]).0);
	}

	// TODO: replace params with transactions!
	evm_test!{test_sender_balance: test_sender_balance_int}
	fn test_sender_balance(factory: Factory) {
		let sender = Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
		let address = contract_address(CreateContractAddress::FromSenderAndNonce, &sender, &U256::zero(), &[]).0;
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.sender = sender.clone();
		params.gas = U256::from(100_000);
		params.code = Some(Arc::new("3331600055".from_hex().unwrap()));
		params.value = ActionValue::Transfer(U256::from(0x7));
		let mut state = get_temp_state_with_factory(factory);
		state.add_balance(&sender, &U256::from(0x100u64), CleanupMode::NoEmpty).unwrap();
		let info = EnvInfo::default();
		let machine = make_frontier_machine(0);
		let mut substate = Substate::new();

		let FinalizationResult { gas_left, .. } = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			ex.create(params, &mut substate, &mut None, &mut NoopTracer, &mut NoopVMTracer, &mut NoopExtTracer).unwrap()
		};

		assert_eq!(gas_left, U256::from(79_975)); // NOTICE: This value will change if the gas model changes, so please update accordingly.
		assert_eq!(state.storage_at(&address, &H256::new()).unwrap(), H256::from(&U256::from(0xf9u64)));
		assert_eq!(state.balance(&sender).unwrap(), U256::from(0xf9));
		assert_eq!(state.balance(&address).unwrap(), U256::from(0x7));
		assert_eq!(substate.contracts_created.len(), 0);

		// TODO: just test state root.
	}

	evm_test!{test_create_contract_out_of_depth: test_create_contract_out_of_depth_int}
	fn test_create_contract_out_of_depth(factory: Factory) {
		// code:
		//
		// 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push 29 bytes?
		// 60 00 - push 0
		// 52
		// 60 1d - push 29
		// 60 03 - push 3
		// 60 17 - push 17
		// f0 - create
		// 60 00 - push 0
		// 55 sstore
		//
		// other code:
		//
		// 60 10 - push 16
		// 80 - duplicate first stack item
		// 60 0c - push 12
		// 60 00 - push 0
		// 39 - copy current code to memory
		// 60 00 - push 0
		// f3 - return

		let code = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d60036017f0600055".from_hex().unwrap();

		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let address = contract_address(CreateContractAddress::FromSenderAndNonce, &sender, &U256::zero(), &[]).0;
		// TODO: add tests for 'callcreate'
		//let next_address = contract_address(&address, &U256::zero());
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.sender = sender.clone();
		params.origin = sender.clone();
		params.gas = U256::from(100_000);
		params.code = Some(Arc::new(code));
		params.value = ActionValue::Transfer(U256::from(100));
		let mut state = get_temp_state_with_factory(factory);
		state.add_balance(&sender, &U256::from(100), CleanupMode::NoEmpty).unwrap();
		let info = EnvInfo::default();
		let machine = make_frontier_machine(0);
		let mut substate = Substate::new();

		let FinalizationResult { gas_left, .. } = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			ex.create(params, &mut substate, &mut None, &mut NoopTracer, &mut NoopVMTracer, &mut NoopExtTracer).unwrap()
		};

		assert_eq!(gas_left, U256::from(62_976)); // NOTICE: This value will change if the gas model changes, so please update accordingly.
		// ended with max depth
		assert_eq!(substate.contracts_created.len(), 0);
	}

	#[test]
	fn test_call_to_precompiled_tracing() {
		// code:
		//
		// 60 00 - push 00 out size
		// 60 00 - push 00 out offset
		// 60 00 - push 00 in size
		// 60 00 - push 00 in offset
		// 60 01 - push 01 value
		// 60 03 - push 03 to
		// 61 ffff - push fff gas
		// f1 - CALL

		let code = "60006000600060006001600361fffff1".from_hex().unwrap();
		let sender = Address::from_str("4444444444444444444444444444444444444444").unwrap();
		let address = Address::from_str("5555555555555555555555555555555555555555").unwrap();

		let mut params = ActionParams::default();
		params.address = address.clone();
		params.code_address = address.clone();
		params.sender = sender.clone();
		params.origin = sender.clone();
		params.gas = U256::from(100_000);
		params.code = Some(Arc::new(code));
		params.value = ActionValue::Transfer(U256::from(100));
		params.call_type = CallType::Call;
		let mut state = get_temp_state();
		state.add_balance(&sender, &U256::from(100), CleanupMode::NoEmpty).unwrap();
		let info = EnvInfo::default();
		let machine = make_byzantium_machine(5);
		let mut substate = Substate::new();
		let mut tracer = ExecutiveTracer::default();
		let mut vm_tracer = ExecutiveVMTracer::toplevel();
		let mut ext_tracer = NoopExtTracer;

		let mut ex = Executive::new(&mut state, &info, &machine);
		let output = BytesRef::Fixed(&mut[0u8;0]);
		ex.call(params, &mut substate, output, &mut tracer, &mut vm_tracer, &mut ext_tracer).unwrap();

		assert_eq!(tracer.drain(), vec![FlatTrace {
			action: trace::Action::Call(trace::Call {
				from: "4444444444444444444444444444444444444444".into(),
				to: "5555555555555555555555555555555555555555".into(),
				value: 100.into(),
				gas: 100_000.into(), // NOTICE: This value will change if the gas model changes, so please update accordingly.
				input: vec![],
				call_type: CallType::Call
			}),
			result: trace::Res::Call(trace::CallResult {
				gas_used: 33021.into(),
				output: vec![]
			}),
			subtraces: 1,
			trace_address: Default::default()
		}, FlatTrace {
			action: trace::Action::Call(trace::Call {
				from: "5555555555555555555555555555555555555555".into(),
				to: "0000000000000000000000000000000000000003".into(),
				value: 1.into(),
				gas: 66560.into(), // NOTICE: This value will change if the gas model changes, so please update accordingly.
				input: vec![],
				call_type: CallType::Call
			}), result: trace::Res::Call(trace::CallResult {
				gas_used: 600.into(),
				output: vec![]
			}),
			subtraces: 0,
			trace_address: vec![0].into_iter().collect(),
		}]);
	}

	#[test]
	// Tracing is not suported in JIT
	fn test_call_to_create() {
		// code:
		//
		// 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push 29 bytes?
		// 60 00 - push 0
		// 52
		// 60 1d - push 29
		// 60 03 - push 3
		// 60 17 - push 23
		// f0 - create
		// 60 00 - push 0
		// 55 sstore
		//
		// other code:
		//
		// 60 10 - push 16
		// 80 - duplicate first stack item
		// 60 0c - push 12
		// 60 00 - push 0
		// 39 - copy current code to memory
		// 60 00 - push 0
		// f3 - return

		let code = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d60036017f0600055".from_hex().unwrap();

		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let address = contract_address(CreateContractAddress::FromSenderAndNonce, &sender, &U256::zero(), &[]).0;
		// TODO: add tests for 'callcreate'
		//let next_address = contract_address(&address, &U256::zero());
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.code_address = address.clone();
		params.sender = sender.clone();
		params.origin = sender.clone();
		params.gas = U256::from(100_000);
		params.code = Some(Arc::new(code));
		params.value = ActionValue::Transfer(U256::from(100));
		params.call_type = CallType::Call;
		let mut state = get_temp_state();
		state.add_balance(&sender, &U256::from(100), CleanupMode::NoEmpty).unwrap();
		let info = EnvInfo::default();
		let machine = make_frontier_machine(5);
		// create the pre-existing contract with default expiry
		let schedule = machine.schedule(info.number);
		state.new_contract(&address, U256::from(0), U256::from(0), info.timestamp + schedule.default_storage_duration);
		let mut substate = Substate::new();
		let mut tracer = ExecutiveTracer::default();
		let mut vm_tracer = ExecutiveVMTracer::toplevel();
		let mut ext_tracer = NoopExtTracer;

		let FinalizationResult { gas_left, .. } = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			let output = BytesRef::Fixed(&mut[0u8;0]);
			ex.call(params, &mut substate, output, &mut tracer, &mut vm_tracer, &mut ext_tracer).unwrap()
		};

		assert_eq!(gas_left, U256::from(47_936)); // NOTICE: This value will change if the gas model changes, so please update accordingly.

		let expected_trace = vec![FlatTrace {
			trace_address: Default::default(),
			subtraces: 1,
			action: trace::Action::Call(trace::Call {
				from: "cd1722f3947def4cf144679da39c4c32bdc35681".into(),
				to: "b010143a42d5980c7e5ef0e4a4416dc098a4fed3".into(),
				value: 100.into(),
				gas: 100000.into(), // NOTICE: This value will change if the gas model changes, so please update accordingly.
				input: vec![],
				call_type: CallType::Call,
			}),
			result: trace::Res::Call(trace::CallResult {
				gas_used: U256::from(52_064),
				output: vec![],
			}),
		}, FlatTrace {
			trace_address: vec![0].into_iter().collect(),
			subtraces: 0,
			action: trace::Action::Create(trace::Create {
				from: "b010143a42d5980c7e5ef0e4a4416dc098a4fed3".into(),
				value: 23.into(),
				gas: 67979.into(), // NOTICE: This value will change if the gas model changes, so please update accordingly.
				init: vec![96, 16, 128, 96, 12, 96, 0, 57, 96, 0, 243, 0, 96, 0, 53, 84, 21, 96, 9, 87, 0, 91, 96, 32, 53, 96, 0, 53, 85]
			}),
			result: trace::Res::Create(trace::CreateResult {
				gas_used: U256::from(40),
				address: Address::from_str("c6d80f262ae5e0f164e5fde365044d7ada2bfa34").unwrap(),
				code: vec![96, 0, 53, 84, 21, 96, 9, 87, 0, 91, 96, 32, 53, 96, 0, 53]
			}),
		}];

		assert_eq!(tracer.drain(), expected_trace);

		let expected_vm_trace = VMTrace {
			parent_step: 0,
			code: vec![124, 96, 16, 128, 96, 12, 96, 0, 57, 96, 0, 243, 0, 96, 0, 53, 84, 21, 96, 9, 87, 0, 91, 96, 32, 53, 96, 0, 53, 85, 96, 0, 82, 96, 29, 96, 3, 96, 23, 240, 96, 0, 85],
			operations: vec![
				VMOperation { pc: 0, instruction: 124, gas_cost: 3.into(), executed: Some(VMExecutedOperation { gas_used: 99997.into(), stack_push: vec_into![U256::from_dec_str("2589892687202724018173567190521546555304938078595079151649957320078677").unwrap()], mem_diff: None, store_diff: None }) },
				VMOperation { pc: 30, instruction: 96, gas_cost: 3.into(), executed: Some(VMExecutedOperation { gas_used: 99994.into(), stack_push: vec_into![0], mem_diff: None, store_diff: None }) },
				VMOperation { pc: 32, instruction: 82, gas_cost: 6.into(), executed: Some(VMExecutedOperation { gas_used: 99988.into(), stack_push: vec_into![], mem_diff: Some(MemoryDiff { offset: 0, data: vec![0, 0, 0, 96, 16, 128, 96, 12, 96, 0, 57, 96, 0, 243, 0, 96, 0, 53, 84, 21, 96, 9, 87, 0, 91, 96, 32, 53, 96, 0, 53, 85] }), store_diff: None }) },
				VMOperation { pc: 33, instruction: 96, gas_cost: 3.into(), executed: Some(VMExecutedOperation { gas_used: 99985.into(), stack_push: vec_into![29], mem_diff: None, store_diff: None }) },
				VMOperation { pc: 35, instruction: 96, gas_cost: 3.into(), executed: Some(VMExecutedOperation { gas_used: 99982.into(), stack_push: vec_into![3], mem_diff: None, store_diff: None }) },
				VMOperation { pc: 37, instruction: 96, gas_cost: 3.into(), executed: Some(VMExecutedOperation { gas_used: 99979.into(), stack_push: vec_into![23], mem_diff: None, store_diff: None }) },
				VMOperation { pc: 39, instruction: 240, gas_cost: 99979.into(), executed: Some(VMExecutedOperation { gas_used: 67939.into(), stack_push: vec_into![U256::from_dec_str("1135198453258042933984631383966629874710669425204").unwrap()], mem_diff: None, store_diff: None }) },
				VMOperation { pc: 40, instruction: 96, gas_cost: 3.into(), executed: Some(VMExecutedOperation { gas_used: 67936.into(), stack_push: vec_into![0], mem_diff: None, store_diff: None }) },
				VMOperation { pc: 42, instruction: 85, gas_cost: 20000.into(), executed: Some(VMExecutedOperation { gas_used: 47936.into(), stack_push: vec_into![], mem_diff: None, store_diff: Some(StorageDiff { location: 0.into(), value: U256::from_dec_str("1135198453258042933984631383966629874710669425204").unwrap() }) }) }
			],
			subs: vec![
				VMTrace {
					parent_step: 6,
					code: vec![96, 16, 128, 96, 12, 96, 0, 57, 96, 0, 243, 0, 96, 0, 53, 84, 21, 96, 9, 87, 0, 91, 96, 32, 53, 96, 0, 53, 85],
					operations: vec![
						VMOperation { pc: 0, instruction: 96, gas_cost: 3.into(), executed: Some(VMExecutedOperation { gas_used: 67976.into(), stack_push: vec_into![16], mem_diff: None, store_diff: None }) },
						VMOperation { pc: 2, instruction: 128, gas_cost: 3.into(), executed: Some(VMExecutedOperation { gas_used: 67973.into(), stack_push: vec_into![16, 16], mem_diff: None, store_diff: None }) },
						VMOperation { pc: 3, instruction: 96, gas_cost: 3.into(), executed: Some(VMExecutedOperation { gas_used: 67970.into(), stack_push: vec_into![12], mem_diff: None, store_diff: None }) },
						VMOperation { pc: 5, instruction: 96, gas_cost: 3.into(), executed: Some(VMExecutedOperation { gas_used: 67967.into(), stack_push: vec_into![0], mem_diff: None, store_diff: None }) },
						VMOperation { pc: 7, instruction: 57, gas_cost: 9.into(), executed: Some(VMExecutedOperation { gas_used: 67958.into(), stack_push: vec_into![], mem_diff: Some(MemoryDiff { offset: 0, data: vec![96, 0, 53, 84, 21, 96, 9, 87, 0, 91, 96, 32, 53, 96, 0, 53] }), store_diff: None }) },
						VMOperation { pc: 8, instruction: 96, gas_cost: 3.into(), executed: Some(VMExecutedOperation { gas_used: 67955.into(), stack_push: vec_into![0], mem_diff: None, store_diff: None }) },
						VMOperation { pc: 10, instruction: 243, gas_cost: 0.into(), executed: Some(VMExecutedOperation { gas_used: 67955.into(), stack_push: vec_into![], mem_diff: None, store_diff: None }) }
					],
					subs: vec![]
				}
			]
		};
		assert_eq!(vm_tracer.drain().unwrap(), expected_vm_trace);
	}

	#[test]
	fn test_trace_reverted_create() {
		// code:
		//
		// 65 60016000fd - push 5 bytes
		// 60 00 - push 0
		// 52 mstore
		// 60 05 - push 5
		// 60 1b - push 27
		// 60 17 - push 23
		// f0 - create
		// 60 00 - push 0
		// 55 sstore
		//
		// other code:
		//
		// 60 01
		// 60 00
		// fd - revert

		let code = "6460016000fd6000526005601b6017f0600055".from_hex().unwrap();

		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let address = contract_address(CreateContractAddress::FromSenderAndNonce, &sender, &U256::zero(), &[]).0;
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.code_address = address.clone();
		params.sender = sender.clone();
		params.origin = sender.clone();
		params.gas = U256::from(100_000);
		params.code = Some(Arc::new(code));
		params.value = ActionValue::Transfer(U256::from(100));
		params.call_type = CallType::Call;
		let mut state = get_temp_state();
		state.add_balance(&sender, &U256::from(100), CleanupMode::NoEmpty).unwrap();
		let info = EnvInfo::default();
		let machine = ::ethereum::new_byzantium_test_machine();
		// create the pre-existing contract with default expiry
		let schedule = machine.schedule(info.number);
		state.new_contract(&address, U256::from(0), U256::from(0), info.timestamp + schedule.default_storage_duration);
		let mut substate = Substate::new();
		let mut tracer = ExecutiveTracer::default();
		let mut vm_tracer = ExecutiveVMTracer::toplevel();
		let mut ext_tracer = NoopExtTracer;

		let FinalizationResult { gas_left, .. } = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			let output = BytesRef::Fixed(&mut[0u8;0]);
			ex.call(params, &mut substate, output, &mut tracer, &mut vm_tracer, &mut ext_tracer).unwrap()
		};

		assert_eq!(gas_left, U256::from(62967)); // NOTICE: This value will change if the gas model changes, so please update accordingly.

		let expected_trace = vec![FlatTrace {
			trace_address: Default::default(),
			subtraces: 1,
			action: trace::Action::Call(trace::Call {
				from: "cd1722f3947def4cf144679da39c4c32bdc35681".into(),
				to: "b010143a42d5980c7e5ef0e4a4416dc098a4fed3".into(),
				value: 100.into(),
				gas: 100_000.into(), // NOTICE: This value will change if the gas model changes, so please update accordingly.
				input: vec![],
				call_type: CallType::Call,
			}),
			result: trace::Res::Call(trace::CallResult {
				gas_used: U256::from(37_033),
				output: vec![],
			}),
		}, FlatTrace {
			trace_address: vec![0].into_iter().collect(),
			subtraces: 0,
			action: trace::Action::Create(trace::Create {
				from: "b010143a42d5980c7e5ef0e4a4416dc098a4fed3".into(),
				value: 23.into(),
				gas: 66_917.into(), // NOTICE: This value will change if the gas model changes, so please update accordingly.
				init: vec![0x60, 0x01, 0x60, 0x00, 0xfd]
			}),
			result: trace::Res::FailedCreate(vm::Error::Reverted.into()),
		}];

		assert_eq!(tracer.drain(), expected_trace);
	}

	#[test]
	fn test_create_contract() {
		// Tracing is not supported in JIT
		// code:
		//
		// 60 10 - push 16
		// 80 - duplicate first stack item
		// 60 0c - push 12
		// 60 00 - push 0
		// 39 - copy current code to memory
		// 60 00 - push 0
		// f3 - return

		let code = "601080600c6000396000f3006000355415600957005b60203560003555".from_hex().unwrap();

		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let address = contract_address(CreateContractAddress::FromSenderAndNonce, &sender, &U256::zero(), &[]).0;
		// TODO: add tests for 'callcreate'
		//let next_address = contract_address(&address, &U256::zero());
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.sender = sender.clone();
		params.origin = sender.clone();
		params.gas = U256::from(100_000);
		params.code = Some(Arc::new(code));
		params.value = ActionValue::Transfer(100.into());
		let mut state = get_temp_state();
		state.add_balance(&sender, &U256::from(100), CleanupMode::NoEmpty).unwrap();
		let info = EnvInfo::default();
		let machine = make_frontier_machine(5);
		let mut substate = Substate::new();
		let mut tracer = ExecutiveTracer::default();
		let mut vm_tracer = ExecutiveVMTracer::toplevel();

		let FinalizationResult { gas_left, .. } = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			ex.create(params.clone(), &mut substate, &mut None, &mut tracer, &mut vm_tracer, &mut NoopExtTracer).unwrap()
		};

		assert_eq!(gas_left, U256::from(99_960)); // NOTICE: This value will change if the gas model changes, so please update accordingly.

		let expected_trace = vec![FlatTrace {
			trace_address: Default::default(),
			subtraces: 0,
			action: trace::Action::Create(trace::Create {
				from: params.sender,
				value: 100.into(),
				gas: params.gas,
				init: vec![96, 16, 128, 96, 12, 96, 0, 57, 96, 0, 243, 0, 96, 0, 53, 84, 21, 96, 9, 87, 0, 91, 96, 32, 53, 96, 0, 53, 85],
			}),
			result: trace::Res::Create(trace::CreateResult {
				gas_used: U256::from(40),
				address: params.address,
				code: vec![96, 0, 53, 84, 21, 96, 9, 87, 0, 91, 96, 32, 53, 96, 0, 53]
			}),
		}];

		assert_eq!(tracer.drain(), expected_trace);

		let expected_vm_trace = VMTrace {
			parent_step: 0,
			code: vec![96, 16, 128, 96, 12, 96, 0, 57, 96, 0, 243, 0, 96, 0, 53, 84, 21, 96, 9, 87, 0, 91, 96, 32, 53, 96, 0, 53, 85],
			operations: vec![
				VMOperation { pc: 0, instruction: 96, gas_cost: 3.into(), executed: Some(VMExecutedOperation { gas_used: 99997.into(), stack_push: vec_into![16], mem_diff: None, store_diff: None }) },
				VMOperation { pc: 2, instruction: 128, gas_cost: 3.into(), executed: Some(VMExecutedOperation { gas_used: 99994.into(), stack_push: vec_into![16, 16], mem_diff: None, store_diff: None }) },
				VMOperation { pc: 3, instruction: 96, gas_cost: 3.into(), executed: Some(VMExecutedOperation { gas_used: 99991.into(), stack_push: vec_into![12], mem_diff: None, store_diff: None }) },
				VMOperation { pc: 5, instruction: 96, gas_cost: 3.into(), executed: Some(VMExecutedOperation { gas_used: 99988.into(), stack_push: vec_into![0], mem_diff: None, store_diff: None }) },
				VMOperation { pc: 7, instruction: 57, gas_cost: 9.into(), executed: Some(VMExecutedOperation { gas_used: 99979.into(), stack_push: vec_into![], mem_diff: Some(MemoryDiff { offset: 0, data: vec![96, 0, 53, 84, 21, 96, 9, 87, 0, 91, 96, 32, 53, 96, 0, 53] }), store_diff: None }) },
				VMOperation { pc: 8, instruction: 96, gas_cost: 3.into(), executed: Some(VMExecutedOperation { gas_used: 99976.into(), stack_push: vec_into![0], mem_diff: None, store_diff: None }) },
				VMOperation { pc: 10, instruction: 243, gas_cost: 0.into(), executed: Some(VMExecutedOperation { gas_used: 99976.into(), stack_push: vec_into![], mem_diff: None, store_diff: None }) }
			],
			subs: vec![]
		};
		assert_eq!(vm_tracer.drain().unwrap(), expected_vm_trace);
	}

	evm_test!{test_create_contract_value_too_high: test_create_contract_value_too_high_int}
	fn test_create_contract_value_too_high(factory: Factory) {
		// code:
		//
		// 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push 29 bytes?
		// 60 00 - push 0
		// 52
		// 60 1d - push 29
		// 60 03 - push 3
		// 60 e6 - push 230
		// f0 - create a contract trying to send 230.
		// 60 00 - push 0
		// 55 sstore
		//
		// other code:
		//
		// 60 10 - push 16
		// 80 - duplicate first stack item
		// 60 0c - push 12
		// 60 00 - push 0
		// 39 - copy current code to memory
		// 60 00 - push 0
		// f3 - return

		let code = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d600360e6f0600055".from_hex().unwrap();

		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let address = contract_address(CreateContractAddress::FromSenderAndNonce, &sender, &U256::zero(), &[]).0;
		// TODO: add tests for 'callcreate'
		//let next_address = contract_address(&address, &U256::zero());
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.sender = sender.clone();
		params.origin = sender.clone();
		params.gas = U256::from(100_000);
		params.code = Some(Arc::new(code));
		params.value = ActionValue::Transfer(U256::from(100));
		let mut state = get_temp_state_with_factory(factory);
		state.add_balance(&sender, &U256::from(100), CleanupMode::NoEmpty).unwrap();
		let info = EnvInfo::default();
		let machine = make_frontier_machine(0);
		let mut substate = Substate::new();

		let FinalizationResult { gas_left, .. } = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			ex.create(params, &mut substate, &mut None, &mut NoopTracer, &mut NoopVMTracer, &mut NoopExtTracer).unwrap()
		};

		assert_eq!(gas_left, U256::from(62_976)); // NOTICE: This value will change if the gas model changes, so please update accordingly.
		assert_eq!(substate.contracts_created.len(), 0);
	}

	evm_test!{test_create_contract_without_max_depth: test_create_contract_without_max_depth_int}
	fn test_create_contract_without_max_depth(factory: Factory) {
		// code:
		//
		// 7c 601080600c6000396000f3006000355415600957005b60203560003555 - push 29 bytes?
		// 60 00 - push 0
		// 52
		// 60 1d - push 29
		// 60 03 - push 3
		// 60 17 - push 17
		// f0 - create
		// 60 00 - push 0
		// 55 sstore
		//
		// other code:
		//
		// 60 10 - push 16
		// 80 - duplicate first stack item
		// 60 0c - push 12
		// 60 00 - push 0
		// 39 - copy current code to memory
		// 60 00 - push 0
		// f3 - return

		let code = "7c601080600c6000396000f3006000355415600957005b60203560003555600052601d60036017f0".from_hex().unwrap();

		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let address = contract_address(CreateContractAddress::FromSenderAndNonce, &sender, &U256::zero(), &[]).0;
		let next_address = contract_address(CreateContractAddress::FromSenderAndNonce, &address, &U256::zero(), &[]).0;
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.sender = sender.clone();
		params.origin = sender.clone();
		params.gas = U256::from(100_000);
		params.code = Some(Arc::new(code));
		params.value = ActionValue::Transfer(U256::from(100));
		let mut state = get_temp_state_with_factory(factory);
		state.add_balance(&sender, &U256::from(100), CleanupMode::NoEmpty).unwrap();
		let info = EnvInfo::default();
		let machine = make_frontier_machine(1024);
		let mut substate = Substate::new();

		{
			let mut ex = Executive::new(&mut state, &info, &machine);
			ex.create(params, &mut substate, &mut None, &mut NoopTracer, &mut NoopVMTracer, &mut NoopExtTracer).unwrap();
		}

		assert_eq!(substate.contracts_created.len(), 1);
		assert_eq!(substate.contracts_created[0], next_address);
	}

	// test is incorrect, mk
	// TODO: fix (preferred) or remove
	evm_test_ignore!{test_aba_calls: test_aba_calls_int}
	fn test_aba_calls(factory: Factory) {
		// 60 00 - push 0
		// 60 00 - push 0
		// 60 00 - push 0
		// 60 00 - push 0
		// 60 18 - push 18
		// 73 945304eb96065b2a98b57a48a06ae28d285a71b5 - push this address
		// 61 03e8 - push 1000
		// f1 - message call
		// 58 - get PC
		// 55 - sstore

		let code_a = "6000600060006000601873945304eb96065b2a98b57a48a06ae28d285a71b56103e8f15855".from_hex().unwrap();

		// 60 00 - push 0
		// 60 00 - push 0
		// 60 00 - push 0
		// 60 00 - push 0
		// 60 17 - push 17
		// 73 0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6 - push this address
		// 61 0x01f4 - push 500
		// f1 - message call
		// 60 01 - push 1
		// 01 - add
		// 58 - get PC
		// 55 - sstore
		let code_b = "60006000600060006017730f572e5295c57f15886f9b263e2f6d2d6c7b5ec66101f4f16001015855".from_hex().unwrap();

		let address_a = Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
		let address_b = Address::from_str("945304eb96065b2a98b57a48a06ae28d285a71b5" ).unwrap();
		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();

		let mut params = ActionParams::default();
		params.address = address_a.clone();
		params.sender = sender.clone();
		params.gas = U256::from(100_000);
		params.code = Some(Arc::new(code_a.clone()));
		params.value = ActionValue::Transfer(U256::from(100_000));

		let mut state = get_temp_state_with_factory(factory);
		state.init_code(&address_a, code_a.clone()).unwrap();
		state.init_code(&address_b, code_b.clone()).unwrap();
		state.add_balance(&sender, &U256::from(100_000), CleanupMode::NoEmpty).unwrap();

		let info = EnvInfo::default();
		let machine = make_frontier_machine(0);
		let mut substate = Substate::new();

		let FinalizationResult { gas_left, .. } = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			ex.call(params, &mut substate, BytesRef::Fixed(&mut []), &mut NoopTracer, &mut NoopVMTracer, &mut NoopExtTracer).unwrap()
		};

		assert_eq!(gas_left, U256::from(73_237)); // NOTICE: This value will change if the gas model changes, so please update accordingly.
		assert_eq!(state.storage_at(&address_a, &H256::from(&U256::from(0x23))).unwrap(), H256::from(&U256::from(1)));
	}

	// test is incorrect, mk
	// TODO: fix (preferred) or remove
	evm_test_ignore!{test_recursive_bomb1: test_recursive_bomb1_int}
	fn test_recursive_bomb1(factory: Factory) {
		// 60 01 - push 1
		// 60 00 - push 0
		// 54 - sload
		// 01 - add
		// 60 00 - push 0
		// 55 - sstore
		// 60 00 - push 0
		// 60 00 - push 0
		// 60 00 - push 0
		// 60 00 - push 0
		// 60 00 - push 0
		// 30 - load address
		// 60 e0 - push e0
		// 5a - get gas
		// 03 - sub
		// f1 - message call (self in this case)
		// 60 01 - push 1
		// 55 - sstore
		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let code = "600160005401600055600060006000600060003060e05a03f1600155".from_hex().unwrap();
		let address = contract_address(CreateContractAddress::FromSenderAndNonce, &sender, &U256::zero(), &[]).0;
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.gas = U256::from(100_000);
		params.code = Some(Arc::new(code.clone()));
		let mut state = get_temp_state_with_factory(factory);
		state.init_code(&address, code).unwrap();
		let info = EnvInfo::default();
		let machine = make_frontier_machine(0);
		let mut substate = Substate::new();

		let FinalizationResult { gas_left, .. } = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			ex.call(params, &mut substate, BytesRef::Fixed(&mut []), &mut NoopTracer, &mut NoopVMTracer, &mut NoopExtTracer).unwrap()
		};

		assert_eq!(gas_left, U256::from(59_870)); // NOTICE: This value will change if the gas model changes, so please update accordingly.
		assert_eq!(state.storage_at(&address, &H256::from(&U256::zero())).unwrap(), H256::from(&U256::from(1)));
		assert_eq!(state.storage_at(&address, &H256::from(&U256::one())).unwrap(), H256::from(&U256::from(1)));
	}

	// test is incorrect, mk
	// TODO: fix (preferred) or remove
	evm_test_ignore!{test_transact_simple: test_transact_simple_int}
	fn test_transact_simple(factory: Factory) {
		let keypair = Random.generate().unwrap();
		let t = Transaction {
			action: Action::Create,
			value: U256::from(17),
			data: "3331600055".from_hex().unwrap(),
			gas: U256::from(100_000),
			gas_price: U256::zero(),
			nonce: U256::zero()
		}.sign(keypair.secret(), None);
		let sender = t.sender();
		let contract = contract_address(CreateContractAddress::FromSenderAndNonce, &sender, &U256::zero(), &[]).0;

		let mut state = get_temp_state_with_factory(factory);
		state.add_balance(&sender, &U256::from(18), CleanupMode::NoEmpty).unwrap();
		let mut info = EnvInfo::default();
		info.gas_limit = U256::from(100_000);
		let machine = make_frontier_machine(0);

		let executed = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			let opts = TransactOptions::with_no_tracing();
			ex.transact(&t, opts).unwrap()
		};

		assert_eq!(executed.gas, U256::from(100_000)); // NOTICE: This value will change if the gas model changes, so please update accordingly.
		assert_eq!(executed.gas_used, U256::from(41_301));
		assert_eq!(executed.refunded, U256::from(58_699));
		assert_eq!(executed.cumulative_gas_used, U256::from(41_301));
		assert_eq!(executed.logs.len(), 0);
		assert_eq!(executed.contracts_created.len(), 0);
		assert_eq!(state.balance(&sender).unwrap(), U256::from(1));
		assert_eq!(state.balance(&contract).unwrap(), U256::from(17));
		assert_eq!(state.nonce(&sender).unwrap(), U256::from(1));
		assert_eq!(state.storage_at(&contract, &H256::new()).unwrap(), H256::from(&U256::from(1)));
	}

	evm_test!{test_transact_invalid_nonce: test_transact_invalid_nonce_int}
	fn test_transact_invalid_nonce(factory: Factory) {
		let keypair = Random.generate().unwrap();
		let t = Transaction {
			action: Action::Create,
			value: U256::from(17),
			data: "3331600055".from_hex().unwrap(),
			gas: U256::from(100_000),
			gas_price: U256::zero(),
			nonce: U256::one()
		}.sign(keypair.secret(), None);
		let sender = t.sender();

		let mut state = get_temp_state_with_factory(factory);
		state.add_balance(&sender, &U256::from(17), CleanupMode::NoEmpty).unwrap();
		let mut info = EnvInfo::default();
		info.gas_limit = U256::from(100_000);
		let machine = make_frontier_machine(0);

		let res = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			let opts = TransactOptions::with_no_tracing();
			ex.transact(&t, opts)
		};

		match res {
			Err(ExecutionError::InvalidNonce { expected, got })
				if expected == U256::zero() && got == U256::one() => (),
			_ => assert!(false, "Expected invalid nonce error.")
		}
	}

	evm_test!{test_transact_gas_limit_reached: test_transact_gas_limit_reached_int}
	fn test_transact_gas_limit_reached(factory: Factory) {
		let keypair = Random.generate().unwrap();
		let t = Transaction {
			action: Action::Create,
			value: U256::from(17),
			data: "3331600055".from_hex().unwrap(),
			gas: U256::from(80_001),
			gas_price: U256::zero(),
			nonce: U256::zero()
		}.sign(keypair.secret(), None);
		let sender = t.sender();

		let mut state = get_temp_state_with_factory(factory);
		state.add_balance(&sender, &U256::from(17), CleanupMode::NoEmpty).unwrap();
		let mut info = EnvInfo::default();
		info.gas_used = U256::from(20_000);
		info.gas_limit = U256::from(100_000);
		let machine = make_frontier_machine(0);

		let res = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			let opts = TransactOptions::with_no_tracing();
			ex.transact(&t, opts)
		};

		match res {
			Err(ExecutionError::BlockGasLimitReached { gas_limit, gas_used, gas })
				if gas_limit == U256::from(100_000) && gas_used == U256::from(20_000) && gas == U256::from(80_001) => (),
			_ => assert!(false, "Expected block gas limit error.")
		}
	}

	evm_test!{test_not_enough_cash: test_not_enough_cash_int}
	fn test_not_enough_cash(factory: Factory) {

		let keypair = Random.generate().unwrap();
		let t = Transaction {
			action: Action::Create,
			value: U256::from(18),
			data: "3331600055".from_hex().unwrap(),
			gas: U256::from(100_000),
			gas_price: U256::one(),
			nonce: U256::zero()
		}.sign(keypair.secret(), None);
		let sender = t.sender();

		let mut state = get_temp_state_with_factory(factory);
		state.add_balance(&sender, &U256::from(100_017), CleanupMode::NoEmpty).unwrap();
		let mut info = EnvInfo::default();
		info.gas_limit = U256::from(100_000);
		let machine = make_frontier_machine(0);

		let res = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			let opts = TransactOptions::with_no_tracing();
			ex.transact(&t, opts)
		};

		match res {
			Err(ExecutionError::NotEnoughCash { required , got })
				if required == U512::from(100_018) && got == U512::from(100_017) => (),
			_ => assert!(false, "Expected not enough cash error. {:?}", res)
		}
	}

	evm_test!{test_keccak: test_keccak_int}
	fn test_keccak(factory: Factory) {
		let code = "6064640fffffffff20600055".from_hex().unwrap();

		let sender = Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
		let address = contract_address(CreateContractAddress::FromSenderAndNonce, &sender, &U256::zero(), &[]).0;
		// TODO: add tests for 'callcreate'
		//let next_address = contract_address(&address, &U256::zero());
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.sender = sender.clone();
		params.origin = sender.clone();
		params.gas = U256::from(0x0186a0);
		params.code = Some(Arc::new(code));
		params.value = ActionValue::Transfer(U256::from_str("0de0b6b3a7640000").unwrap());
		let mut state = get_temp_state_with_factory(factory);
		state.add_balance(&sender, &U256::from_str("152d02c7e14af6800000").unwrap(), CleanupMode::NoEmpty).unwrap();
		let info = EnvInfo::default();
		let machine = make_frontier_machine(0);
		let mut substate = Substate::new();

		let result = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			ex.create(params, &mut substate, &mut None, &mut NoopTracer, &mut NoopVMTracer, &mut NoopExtTracer)
		};

		match result {
			Err(_) => {},
			_ => panic!("Expected OutOfGas"),
		}
	}

	evm_test!{test_revert: test_revert_int}
	fn test_revert(factory: Factory) {
		let contract_address = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let sender = Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();
		// EIP-140 test case
		let code = "6c726576657274656420646174616000557f726576657274206d657373616765000000000000000000000000000000000000600052600e6000fd".from_hex().unwrap();
		let returns = "726576657274206d657373616765".from_hex().unwrap();
		let mut state = get_temp_state_with_factory(factory.clone());
		state.add_balance(&sender, &U256::from_str("152d02c7e14af68000000").unwrap(), CleanupMode::NoEmpty).unwrap();
		state.commit().unwrap();

		let mut params = ActionParams::default();
		params.address = contract_address.clone();
		params.sender = sender.clone();
		params.origin = sender.clone();
		params.gas = U256::from(20025);
		params.code = Some(Arc::new(code));
		params.value = ActionValue::Transfer(U256::zero());
		let info = EnvInfo::default();
		let machine = ::ethereum::new_byzantium_test_machine();
		// create the pre-existing contract with default expiry
		let schedule = machine.schedule(info.number);
		state.new_contract(&contract_address, U256::from(0), U256::from(0), info.timestamp + schedule.default_storage_duration);
		let mut substate = Substate::new();

		let mut output = [0u8; 14];
		let FinalizationResult { gas_left: result, .. } = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			ex.call(params, &mut substate, BytesRef::Fixed(&mut output), &mut NoopTracer, &mut NoopVMTracer, &mut NoopExtTracer).unwrap()
		};

		assert_eq!(result, U256::from(1));
		assert_eq!(output[..], returns[..]);
		assert_eq!(state.storage_at(&contract_address, &H256::from(&U256::zero())).unwrap(), H256::from(&U256::from(0)));
	}

	fn wasm_sample_code() -> Arc<Vec<u8>> {
		Arc::new(
			"0061736d01000000010d0360027f7f0060017f0060000002270303656e7603726574000003656e760673656e646572000103656e76066d656d6f727902010110030201020404017000000501000708010463616c6c00020901000ac10101be0102057f017e4100410028020441c0006b22043602042004412c6a41106a220041003602002004412c6a41086a22014200370200200441186a41106a22024100360200200441186a41086a220342003703002004420037022c2004410036021c20044100360218200441186a1001200020022802002202360200200120032903002205370200200441106a2002360200200441086a200537030020042004290318220537022c200420053703002004411410004100200441c0006a3602040b0b0a010041040b0410c00000"
			.from_hex()
			.unwrap()
		)
	}

	#[test]
	fn wasm_activated_test() {
		let contract_address = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let sender = Address::from_str("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6").unwrap();

		let mut state = get_temp_state();
		state.add_balance(&sender, &U256::from(10000000000u64), CleanupMode::NoEmpty).unwrap();
		state.commit().unwrap();

		let mut params = ActionParams::default();
		params.origin = sender.clone();
		params.sender = sender.clone();
		params.address = contract_address.clone();
		params.gas = U256::from(20025);
		params.code = Some(wasm_sample_code());

		let mut info = EnvInfo::default();

		// 100 > 10
		info.number = 100;

		// Network with wasm activated at block 10
		let machine = ::ethereum::new_kovan_wasm_test_machine();
		let mut ext_tracer = NoopExtTracer;

		let mut output = [0u8; 20];
		let FinalizationResult { gas_left: result, .. } = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			ex.call(params.clone(), &mut Substate::new(), BytesRef::Fixed(&mut output), &mut NoopTracer, &mut NoopVMTracer, &mut ext_tracer).unwrap()
		};

		assert_eq!(result, U256::from(15781)); // NOTICE: This value will change if the gas model changes, so please update accordingly.
		// Transaction successfully returned sender
		assert_eq!(output[..], sender[..]);

		// 1 < 10
		info.number = 1;

		let mut output = [0u8; 20];
		let FinalizationResult { gas_left: result, .. } = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			ex.call(params, &mut Substate::new(), BytesRef::Fixed(&mut output), &mut NoopTracer, &mut NoopVMTracer, &mut ext_tracer).unwrap()
		};

		assert_eq!(result, U256::from(20025));
		// Since transaction errored due to wasm was not activated, result is just empty
		assert_eq!(output[..], [0u8; 20][..]);
	}

	// read / write via sload and sstore
	evm_test!{test_ext_tracer_rw: test_ext_tracer_rw_int}
	fn test_ext_tracer_rw(factory: Factory) {
		// 60 01 ; push 1
		// 60 00 ; push 0
		// 54 ; sload
		// 01 ; add
		// 60 01 ; push 1
		// 55 ; sstore
		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let code = "600160005401600155".from_hex().unwrap();
		let address = contract_address(CreateContractAddress::FromSenderAndNonce, &sender, &U256::zero(), &[]).0;
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.gas = U256::from(100_000);
		params.code = Some(Arc::new(code.clone()));
		let mut state = get_temp_state_with_factory(factory);
		state.init_code(&address, code).unwrap();
		let info = EnvInfo::default();
		let machine = make_frontier_machine(0);
		let mut substate = Substate::new();
		let mut ext_tracer = FullExtTracer::new();

		let FinalizationResult { gas_left, .. } = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			ex.call(params, &mut substate, BytesRef::Fixed(&mut []), &mut NoopTracer, &mut NoopVMTracer, &mut ext_tracer).unwrap()
		};

		// Ignore gas used.
		assert_eq!(state.storage_at(&address, &H256::from(&U256::zero())).unwrap(), H256::from(&U256::from(0)));
		assert_eq!(state.storage_at(&address, &H256::from(&U256::one())).unwrap(), H256::from(&U256::from(1)));
		let expected_ext_trace = FullTracerCallTrace {
			contract: address.clone(),
			trace: vec![
				// SLOAD(0)
				FullTracerRecord::Read(H256::from(0)),
				// SSTORE(1): Interpreter<Cost>::exec_instruction SSTORE reads
				//  first to see if there is a refund for clearing persistent
				//  memory;
				FullTracerRecord::Read(H256::from(1)),
				//  State<B>::set_storage reads to see if new value is change before
				FullTracerRecord::Read(H256::from(1)),
				//  ... actually doing the store.
				FullTracerRecord::Write(H256::from(1)),
			],
			// TODO(bsy): Interpreter<Cost>::exec_stack_instructions should see if
			// the new value is zero first, before fetching the old value.
		};
		let trace = ext_tracer.drain();
		assert_eq!(trace, expected_ext_trace);
	}

	// The exists and exists_and_not_full queries are not directly referenced from
	// Interpreter<Cost>, but are invoked indirectly in gasometer via CALL or SUICIDE, when
	// checking for the target address of the call.  Which of exists or exists_and_not_full
	// will be used depends on schedule.no_empty.
	//
	// call
	evm_test!{test_ext_tracer_call: test_ext_tracer_call_int}
	fn test_ext_tracer_call(factory: Factory) {
		// 60 00 ; retLength
		// 80 ; retOffset
		// 80 ; argsLength
		// 80 ; argsOffset
		// 80 ; value
		// 63 60 00 80 3f - push other code, which is just push 0; dup; ret
		// 60 00 - push 0
		// 52 - mstore
		// 60 04 - push 4 init_size
		// 60 1c - push 28=32-4 init_off
		// 60 17 - push 17 endowment
		// f0 - create ; addr
		// 80 - dup contract addr
		// 60 00 - push 0
		// 55 sstore ; so we can retrieve it for comparison
		// 60 ff ; gas to be used for the call
		// f1 ; message call
		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let code = "600080808080636000803f6000526004601c6017f08060005560fff1".from_hex().unwrap();
		let address = contract_address(CreateContractAddress::FromSenderAndNonce, &sender, &U256::zero(), &[]).0;
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.gas = U256::from(100_000);
		params.code = Some(Arc::new(code.clone()));
		let mut state = get_temp_state_with_factory(factory);
		state.init_code(&address, code).unwrap();
		let info = EnvInfo::default();
		let machine = make_frontier_machine(0);
		let mut substate = Substate::new();
		let mut ext_tracer = FullExtTracer::new();

		let FinalizationResult { gas_left, .. } = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			ex.call(params, &mut substate, BytesRef::Fixed(&mut []), &mut NoopTracer, &mut NoopVMTracer, &mut ext_tracer).unwrap()
		};

		let subcontract = state.storage_at(&address, &H256::from(&U256::zero())).unwrap();
		// Ignore gas used.
		let expected_ext_trace = FullTracerCallTrace {
			contract: address.clone(),
			trace: vec![
				// CREATE invokes ext.balance to see if there's enough endowment
				FullTracerRecord::Balance(address.clone()),
				// SSTORE(0) subcontract addr
				FullTracerRecord::Read(H256::from(0)),
				FullTracerRecord::Read(H256::from(0)),
				FullTracerRecord::Write(H256::from(0)),
				// Side-effect of CALL
				//  gasometer<Gas>::requirements, before actual execution
				FullTracerRecord::Exists(subcontract.into()),
				//  Interpreter<Cost>::exec_instruction has_balance check call
				//  value transfer
				FullTracerRecord::Balance(address.clone()),
			],
		};
		let trace = ext_tracer.drain();
		assert_eq!(trace, expected_ext_trace);
	}

	// balance
	evm_test!{test_ext_tracer_bal: test_ext_tracer_bal_int}
	fn test_ext_tracer_bal(factory: Factory) {
		// 30 ; address
		// 31 ; balance
		// 50 ; pop
		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let code = "303150".from_hex().unwrap();
		let address = contract_address(CreateContractAddress::FromSenderAndNonce, &sender, &U256::zero(), &[]).0;
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.gas = U256::from(100_000);
		params.code = Some(Arc::new(code.clone()));
		let mut state = get_temp_state_with_factory(factory);
		state.init_code(&address, code).unwrap();
		let info = EnvInfo::default();
		let machine = make_frontier_machine(0);
		let mut substate = Substate::new();
		let mut ext_tracer = FullExtTracer::new();

		let FinalizationResult { gas_left, .. } = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			ex.call(params, &mut substate, BytesRef::Fixed(&mut []), &mut NoopTracer, &mut NoopVMTracer, &mut ext_tracer).unwrap()
		};

		// Ignore gas used.
		let expected_ext_trace = FullTracerCallTrace {
			contract: address.clone(),
			trace: vec![
				// BALANCE()
				FullTracerRecord::Balance(address.clone()),
			],
		};
		let trace = ext_tracer.drain();
		assert_eq!(trace, expected_ext_trace);
	}

	// read / write via sload and sstore -- counting tracer
	evm_test!{test_ext_tracer_counting: test_ext_tracer_counting_int}
	fn test_ext_tracer_counting(factory: Factory) {
		// 60 01 ; push 1
		// 60 00 ; push 0
		// 54 ; sload
		// 01 ; add
		// 60 01 ; push 1
		// 55 ; sstore
		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let code = "600160005401600155".from_hex().unwrap();
		let address = contract_address(CreateContractAddress::FromSenderAndNonce, &sender, &U256::zero(), &[]).0;
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.gas = U256::from(100_000);
		params.code = Some(Arc::new(code.clone()));
		let mut state = get_temp_state_with_factory(factory);
		state.init_code(&address, code).unwrap();
		let info = EnvInfo::default();
		let machine = make_frontier_machine(0);
		let mut substate = Substate::new();
		let mut ext_tracer = CountingTracer::new();

		let FinalizationResult { gas_left, .. } = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			ex.call(params, &mut substate, BytesRef::Fixed(&mut []), &mut NoopTracer, &mut NoopVMTracer, &mut ext_tracer).unwrap()
		};

		// Ignore gas used.
		assert_eq!(state.storage_at(&address, &H256::from(&U256::zero())).unwrap(), H256::from(&U256::from(0)));
		assert_eq!(state.storage_at(&address, &H256::from(&U256::one())).unwrap(), H256::from(&U256::from(1)));
		let expected_ext_trace = (2, 1);
		let trace = ext_tracer.get_rw_counts();
		assert_eq!(trace, expected_ext_trace);
	}

	// read / write via sload and sstore; more instructions -- counting tracer
	evm_test!{test_ext_tracer_counting2: test_ext_tracer_counting2_int}
	fn test_ext_tracer_counting2(factory: Factory) {
		// 60 01 ; push 1
		// 60 00 ; push 0
		// 54 ; sload
		// 01 ; add
		// 60 01 ; push 1
		// 54 ; sload
		// 01 ; add
		// 60 02 ; push 2
		// 54 ; sload
		// 01 ; add
		// 60 03 ; push 3
		// 54 ; sload
		// 01 ; add
		// 60 04 ; push 4
		// 55 ; sstore
		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let code = "600160005401600154016002540160035401600455".from_hex().unwrap();
		let address = contract_address(CreateContractAddress::FromSenderAndNonce, &sender, &U256::zero(), &[]).0;
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.gas = U256::from(100_000);
		params.code = Some(Arc::new(code.clone()));
		let mut state = get_temp_state_with_factory(factory);
		state.init_code(&address, code).unwrap();
		let info = EnvInfo::default();
		let machine = make_frontier_machine(0);
		let mut substate = Substate::new();
		let mut ext_tracer = CountingTracer::new();

		let FinalizationResult { gas_left, .. } = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			ex.call(params, &mut substate, BytesRef::Fixed(&mut []), &mut NoopTracer, &mut NoopVMTracer, &mut ext_tracer).unwrap()
		};

		// Ignore gas used.
		assert_eq!(state.storage_at(&address, &H256::from(&U256::zero())).unwrap(), H256::from(&U256::from(0)));
		assert_eq!(state.storage_at(&address, &H256::from(&U256::from(4))).unwrap(), H256::from(&U256::from(1)));
		let expected_ext_trace = (5, 1);
		let trace = ext_tracer.get_rw_counts();
		assert_eq!(trace, expected_ext_trace);
	}

	// read / write via sload and sstore; more writes -- counting tracer
	evm_test!{test_ext_tracer_counting3: test_ext_tracer_counting3_int}
	fn test_ext_tracer_counting3(factory: Factory) {
		// 60 05 ; push 5
		// 60 00 ; push 0
		// 55 ; sstore
		// 60 04 ; push 4
		// 60 01 ; push 1
		// 55 ; sstore
		// 60 03 ; push 3
		// 60 02 ; push 2
		// 55 ; sstore
		// 60 02 ; push 2
		// 60 03 ; push 3
		// 55 ; sstore
		// 60 01 ; push 1
		// 60 04 ; push 4
		// 55 ; sstore
		// 60 00 ; push 0
		// 54 ; sload
		// 60 01 ; push 1
		// 54 ; sload
		// 60 02 ; push 2
		// 54 ; sload
		// 60 03 ; push 3
		// 54 ; sload
		// 60 04 ; push 4
		// 54 ; sload
		// 01 ; add
		// 01 ; add
		// 01 ; add
		// 01 ; add
		// 60 05 ; push 5
		// 55 ; sstore
		let sender = Address::from_str("cd1722f3947def4cf144679da39c4c32bdc35681").unwrap();
		let code = "6005600055600460015560036002556002600355600160045560005460015460025460035460045401010101600555".from_hex().unwrap();
		let address = contract_address(CreateContractAddress::FromSenderAndNonce, &sender, &U256::zero(), &[]).0;
		let mut params = ActionParams::default();
		params.address = address.clone();
		params.gas = U256::from(200_000);
		params.code = Some(Arc::new(code.clone()));
		let mut state = get_temp_state_with_factory(factory);
		state.init_code(&address, code).unwrap();
		let info = EnvInfo::default();
		let machine = make_frontier_machine(0);
		let mut substate = Substate::new();
		let mut ext_tracer = CountingTracer::new_extended(100, 0.0001);

		let FinalizationResult { gas_left, .. } = {
			let mut ex = Executive::new(&mut state, &info, &machine);
			ex.call(params, &mut substate, BytesRef::Fixed(&mut []), &mut NoopTracer, &mut NoopVMTracer, &mut ext_tracer).unwrap()
		};

		// Ignore gas used.
		assert_eq!(state.storage_at(&address, &H256::from(&U256::zero())).unwrap(), H256::from(&U256::from(5)));
		assert_eq!(state.storage_at(&address, &H256::from(&U256::from(4))).unwrap(), H256::from(&U256::from(1)));
		let expected_ext_trace = (6, 6);
		let trace = ext_tracer.get_rw_counts();
		assert_eq!(trace, expected_ext_trace);
	}
}
