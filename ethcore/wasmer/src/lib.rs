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
extern crate wasmer_runtime;
extern crate wasmer_runtime_core;

mod parser;
mod runtime;
mod wasi;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod benches;

use parity_wasm::elements;
use runtime::{Result, Runtime, RuntimeContext};
use vm::{ActionParams, GasLeft, ReturnData};

use ethereum_types::U256;
use std::ffi::c_void;
use std::convert::TryInto;

use wasmer_runtime::{Module};
use wasmer_runtime_core::{error, memory, memory::MemoryView, Instance, module, module::ModuleInfo};
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

impl vm::Vm for WasmRuntime {
	fn prepare(&mut self, params: &ActionParams, ext: &mut vm::Ext) -> vm::Result<()> {
		
		let is_create = ext.is_create();
		
		// Explicitly split the input into code and data
		let (_, code, data) = parser::payload(
			&params,
			ext.schedule().wasm(),
		)?;

		let mut module = wasmer_runtime::compile(
			&code,
		).unwrap();

		if is_create {
			subst_main_call(&mut module);
		}

		self.module = Some(module);
		self.data = data.to_vec();

		Ok(())
	}

	fn exec(&mut self, params: ActionParams, ext: &mut vm::Ext) -> vm::Result<GasLeft> {
		
		let is_create = ext.is_create();

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
			let mut descriptor = wasmer_runtime_core::types::MemoryDescriptor {
				minimum: wasmer_runtime_core::units::Pages(0),
				maximum: Some(wasmer_runtime_core::units::Pages(0)),
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
					Err(wasmer_runtime_core::error::CallError::Runtime(ref trap)) => {
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
fn subst_main_call(module: &mut Module) {

	let module_info = module.info();

	let start_fn_idx = match func_index(module_info, "_start") {
		Some(idx) => idx,
		None => return,
	};
	let deploy_fn_idx = match func_index(module_info, "_mantle_deploy") {
		Some(idx) => idx,
		None => return,
	};
	let mut main_fn_idx = match func_index(module_info, "main") {
		Some(idx) => idx,
		None => return,
	};

	// TODO: replace function index

}

/// Returns the function index of an export by name.
fn func_index(module: &ModuleInfo, name: &str) -> Option<module::ExportIndex> {
	if let Some((_, export_idx)) = module.exports.get_key_value(name) {
		match export_idx {
			module::ExportIndex::Func(func_idx) => {
				return Some(module::ExportIndex::Func(*func_idx));
			},
			_ => return None,
		};
	}
	None
}
