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

//! Wasmer Runtime
#![feature(specialization, type_ascription)]
#![feature(test)]

extern crate bcfs;
extern crate blockchain_traits;
extern crate byteorder;
extern crate common_types;
extern crate ethereum_types;
extern crate keccak_hash as hash;
extern crate mantle_types;
#[macro_use]
extern crate log;
extern crate parity_wasm;
extern crate pwasm_utils as wasm_utils;
extern crate vm;
extern crate wasi_types;
extern crate wasm_macros;
extern crate wasmer_clif_backend;
extern crate wasmer_runtime;
extern crate wasmer_runtime_core;
extern crate wasmi;

mod env;
mod parser;
mod runtime;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod benches;

use parity_wasm::elements;
use runtime::{Result, Runtime, RuntimeContext};
use vm::{ActionParams, GasLeft, ReturnData};

use ethereum_types::U256;
use std::ffi::c_void;

use wasmer_runtime::{error, instantiate, memory, memory::MemoryView, Instance, Module};
use wasmer_runtime_core::backend::Compiler;

/// Wasmer runtime instance
#[derive(Default)]
pub struct WasmRuntime {
	module: Option<Module>,
	data: Vec<u8>,
}

enum ExecutionOutcome {
	Suicide,
	Return,
	NotSpecial,
}

impl WasmRuntime {
	// Only cranelift supported for now
	pub fn get_compiler(&self) -> impl Compiler {
		use wasmer_clif_backend::CraneliftCompiler as DefaultCompiler;
		DefaultCompiler::new()
	}
}

impl vm::Vm for WasmRuntime {
	fn prepare(&mut self, params: &ActionParams, ext: &mut vm::Ext) -> vm::Result<()> {
		// Explicitly split the input into code and data
		let (_, code, data) = parser::payload(&params, ext.schedule().wasm())?;

		self.module = Some(wasmer_runtime::compile_with(&code, &self.get_compiler()).unwrap());
		self.data = data.to_vec();

		Ok(())
	}

	fn exec(&mut self, params: ActionParams, ext: &mut vm::Ext) -> vm::Result<GasLeft> {
		let is_create = ext.is_create();

		if is_create {
			let (mut module, _, _) = parser::payload(&params, ext.schedule().wasm())?;
			subst_main_call(&mut module);
		}

		if let Some(module) = &self.module {
			let adjusted_gas_limit = params.gas * U256::from(ext.schedule().wasm().opcodes_div)
				/ U256::from(ext.schedule().wasm().opcodes_mul);

			if adjusted_gas_limit > ::std::u64::MAX.into() {
				return Err(vm::Error::Wasm(
					"Wasm runtime cannot run contracts with gas (wasm adjusted) >= 2^64".to_owned(),
				));
			}

			let mut runtime = Runtime::with_params(
				ext,
				adjusted_gas_limit.low_u64(), // cannot overflow, checked above
				self.data.clone(),
				RuntimeContext {
					address: params.address,
					sender: params.sender,
					origin: params.origin,
					code_address: params.code_address,
					value: params.value.value(),
					value_str: params.value.value().as_u64().to_string(),
				},
			);

			// Default memory descriptor
			let mut descriptor = wasmer_runtime::wasm::MemoryDescriptor {
				minimum: wasmer_runtime::units::Pages(0),
				maximum: Some(wasmer_runtime::units::Pages(0)),
				shared: false,
			};

			// Get memory descriptor from code import
			// TODO handle case if more than 1 present
			for (_, (_, expected_memory_desc)) in &module.info().imported_memories {
				descriptor = *expected_memory_desc;
			}

			let mem_obj = memory::Memory::new(descriptor).unwrap();
			let memory_view: MemoryView<u8> = mem_obj.view();
			let initial_memory_size = memory_view.len() / 65535;

			let raw_ptr = &mut runtime as *mut _ as *mut c_void;
			let import_object = runtime::imports::get_import_object(mem_obj, raw_ptr);

			// Create the wasmer runtime instance to call function
			let instance = module.instantiate(&import_object).unwrap();

			// cannot overflow if static_region < 2^16,
			// initial_memory ∈ [0..2^32))
			// total_charge <- static_region * 2^32 * 2^16
			// total_charge ∈ [0..2^64) if static_region ∈ [0..2^16)
			// qed

			assert!(runtime.schedule().wasm().initial_mem_cost < 1 << 16);
			let gas_result = runtime
				.charge(|s| Some(initial_memory_size as u64 * s.wasm().initial_mem_cost as u64));

			// Hacky, but we need to return error is gas limit is hit
			if let Err(gas_error) = gas_result {
				return Err(vm::Error::Wasm(format!("Out of gas: {:?}", gas_error)));
			};

			let (gas_left, result) = {
				let invoke_result = instance.call("_start", &[]);

				let mut execution_outcome = ExecutionOutcome::NotSpecial;
				match &invoke_result {
					Ok(_) => (),
					Err(wasmer_runtime::error::CallError::Runtime(ref trap)) => {
						// This flag only set from a proc exit, if not set, assume panic and we need to revert
						if !runtime.should_persist {
							runtime.should_revert = true;
						}
						execution_outcome = ExecutionOutcome::Return;
					}
					_ => (),
				}

				if let (ExecutionOutcome::NotSpecial, Err(e)) = (execution_outcome, invoke_result) {
					return Err(vm::Error::Wasm(format!("Wasm contract trap: {:?}", e)));
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
				std::sync::Arc::try_unwrap(params.code.unwrap_or_default())
					.unwrap_or_else(|arc| arc.to_vec())
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
		} else {
			return Err(vm::Error::Wasm(format!("Executing an unprepared contract")));
		}
	}
}

/// Replaces the call to `main` in `_start` with one to `_mantle_deploy`.
fn subst_main_call(module: &mut elements::Module) {
	let start_fn_idx = match func_index(module, "_start") {
		Some(idx) => idx,
		None => return,
	};
	let deploy_fn_idx = match func_index(module, "_mantle_deploy") {
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
