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

//! Wasm Interpreter
#![feature(specialization, type_ascription)]
#![feature(test)]

extern crate base64;
extern crate bcfs;
extern crate byteorder;
extern crate common_types;
extern crate ethereum_types;
extern crate keccak_hash as hash;
#[macro_use]
extern crate log;
extern crate parity_wasm;
extern crate pwasm_utils as wasm_utils;
extern crate vm;
extern crate wasi_types;
extern crate wasm_macros;
extern crate wasmi;

mod env;
mod parser;
mod runtime;

#[cfg(test)]
mod tests;
mod wasi;

#[cfg(test)]
mod benches;

use parity_wasm::elements;
use vm::{ActionParams, GasLeft, ReturnData};
use wasmi::{Error as InterpreterError, Trap};

use runtime::{Result, Runtime, RuntimeContext};

use ethereum_types::U256;

/// Wrapped interpreter error
#[derive(Debug)]
pub enum Error {
	Interpreter(InterpreterError),
	Trap(Trap),
}

impl From<InterpreterError> for Error {
	fn from(e: InterpreterError) -> Self {
		Error::Interpreter(e)
	}
}

impl From<Trap> for Error {
	fn from(e: Trap) -> Self {
		Error::Trap(e)
	}
}

impl From<Error> for vm::Error {
	fn from(e: Error) -> Self {
		match e {
			Error::Interpreter(e) => vm::Error::Wasm(format!("Wasm runtime error: {:?}", e)),
			Error::Trap(e) => vm::Error::Wasm(format!("Wasm contract trap: {:?}", e)),
		}
	}
}

/// Wasm interpreter instance
pub struct WasmInterpreter;

impl From<runtime::Error> for vm::Error {
	fn from(e: runtime::Error) -> Self {
		vm::Error::Wasm(format!("Wasm runtime error: {:?}", e))
	}
}

enum ExecutionOutcome {
	Suicide,
	Return,
	NotSpecial,
}

impl vm::Vm for WasmInterpreter {
	fn prepare(&mut self, params: &ActionParams, ext: &mut dyn vm::Ext) -> vm::Result<()> {
		Ok(())
	}

	fn exec(&mut self, params: ActionParams, ext: &mut dyn vm::Ext) -> vm::Result<GasLeft> {
		let is_create = ext.is_create();

		let parser::ParsedModule {
			mut module,
			code,
			data,
		} = parser::payload(
			&params,
			ext.schedule().wasm(),
			if is_create {
				Some(subst_main_call)
			} else {
				None
			},
		)?;

		let loaded_module =
			wasmi::Module::from_parity_wasm_module(module).map_err(Error::Interpreter)?;

		let instantiation_resolver = env::ImportResolver::with_limit(<u32>::max_value());

		let module_instance = wasmi::ModuleInstance::new(
			&loaded_module,
			&wasmi::ImportsBuilder::new()
				.with_resolver("env", &instantiation_resolver)
				.with_resolver("wasi_unstable", &instantiation_resolver),
		)
		.map_err(Error::Interpreter)?;

		let adjusted_gas = params.gas * U256::from(ext.schedule().wasm().opcodes_div)
			/ U256::from(ext.schedule().wasm().opcodes_mul);

		if adjusted_gas > ::std::u64::MAX.into() {
			return Err(vm::Error::Wasm(
				"Wasm interpreter cannot run contracts with gas (wasm adjusted) >= 2^64".to_owned(),
			));
		}

		let initial_memory = instantiation_resolver
			.memory_size()
			.map_err(Error::Interpreter)?;
		trace!(target: "wasm", "Contract requested {:?} pages of initial memory", initial_memory);

		let (gas_left, result) = {
			let mut runtime = Runtime::with_params(
				ext,
				instantiation_resolver.memory_ref(),
				// cannot overflow, checked above
				adjusted_gas.low_u64(),
				data.to_vec(),
				RuntimeContext {
					address: params.address,
					sender: params.sender,
					origin: params.origin,
					code_address: params.code_address,
					value: params.value.value(),
					value_str: params.value.value().as_u64().to_string(),
					aad: params.aad.clone(),
				},
			);

			// cannot overflow if static_region < 2^16,
			// initial_memory ∈ [0..2^32)
			// total_charge <- static_region * 2^32 * 2^16
			// total_charge ∈ [0..2^64) if static_region ∈ [0..2^16)
			// qed
			assert!(runtime.schedule().wasm().initial_mem_cost < 1 << 16);
			runtime.charge(|s| Some(initial_memory as u64 * s.wasm().initial_mem_cost as u64))?;

			let module_instance = module_instance
				.run_start(&mut runtime)
				.map_err(Error::Trap)?;

			let invoke_result = module_instance.invoke_export("_start", &[], &mut runtime);

			let mut execution_outcome = ExecutionOutcome::NotSpecial;
			match &invoke_result {
				Ok(_) => (),
				Err(InterpreterError::Trap(ref trap)) => match *trap.kind() {
					wasmi::TrapKind::Host(ref boxed) => {
						let ref runtime_err = boxed
							.downcast_ref::<runtime::Error>()
							.expect("Host errors other than runtime::Error never produced; qed");

						match &**runtime_err {
							runtime::Error::Suicide => {
								execution_outcome = ExecutionOutcome::Suicide;
							}
							runtime::Error::Return => {
								execution_outcome = ExecutionOutcome::Return;
							}
							_ => (),
						}
					}
					wasmi::TrapKind::Unreachable => {
						runtime.should_revert = true;
						execution_outcome = ExecutionOutcome::Return;
					}
					_ => (),
				},
				Err(InterpreterError::Function(_)) if is_create => {
					// deploy function need not exist
					execution_outcome = ExecutionOutcome::Return;
				}
				_ => (),
			}

			if let (ExecutionOutcome::NotSpecial, Err(e)) = (execution_outcome, invoke_result) {
				trace!(target: "wasm", "Error executing contract: {:?}", e);
				return Err(vm::Error::from(Error::from(e)));
			}

			(
				runtime
					.gas_left()
					.expect("Cannot fail since it was not updated since last charge"),
				runtime.into_result(),
			)
		};

		let gas_left = U256::from(gas_left) * U256::from(ext.schedule().wasm().opcodes_mul)
			/ U256::from(ext.schedule().wasm().opcodes_div);

		let apply_state = !result.is_err();
		let output = if is_create {
			code.to_vec()
		} else {
			result.clone().unwrap_or_else(std::convert::identity) // Result<Vec<u8>, Vec<u8>> -> Vec<u8>
		};
		{
			std::str::from_utf8(&result.clone().unwrap_or_else(std::convert::identity));
		}
		let output_len = output.len();
		Ok(GasLeft::NeedsReturn {
			gas_left,
			apply_state,
			data: ReturnData::new(output, 0, output_len),
		})
	}
}

/// Replaces the call to `main` in `_start` with one to `_oasis_deploy`.
fn subst_main_call(module: &mut elements::Module) {
	let start_fn_idx = match func_index(module, "_start") {
		Some(idx) => idx,
		None => return,
	};
	let deploy_fn_idx = match func_index(module, "_oasis_deploy") {
		Some(idx) => idx,
		None => return,
	};
	let main_fn_idx = match func_index(module, "main") {
		Some(idx) => idx,
		None => return,
	};

	let import_section_len: usize = module
		.import_section()
		.map(|import| {
			import
				.entries()
				.iter()
				.filter(|entry| match entry.external() {
					&elements::External::Function(_) => true,
					_ => false,
				})
				.count()
		})
		.unwrap_or_default();

	let mut start_fn = match module
		.code_section_mut()
		.map(|s| &mut s.bodies_mut()[start_fn_idx as usize - import_section_len])
	{
		Some(f) => f,
		None => return,
	};

	for instr in start_fn.code_mut().elements_mut() {
		if let elements::Instruction::Call(ref mut idx) = instr {
			if *idx == main_fn_idx {
				*idx = deploy_fn_idx;
			}
		}
	}
}

/// Returns the function index of an export by name.
fn func_index(module: &elements::Module, name: &str) -> Option<u32> {
	module
		.export_section()
		.iter()
		.flat_map(|s| s.entries())
		.find_map(|export| {
			if export.field() == name {
				match export.internal() {
					elements::Internal::Function(idx) => Some(*idx),
					_ => None,
				}
			} else {
				None
			}
		})
}
