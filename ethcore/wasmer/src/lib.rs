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

extern crate byteorder;
// extern crate ethcore_logger;
extern crate ethereum_types;
extern crate keccak_hash as hash;
#[macro_use]
extern crate log;
// extern crate libc;
extern crate parity_wasm;
extern crate pwasm_utils as wasm_utils;
extern crate vm;
extern crate wasmer_runtime;
extern crate wasmer_runtime_core;

mod panic_payload;
mod parser;
mod runtime;
#[cfg(test)]
mod tests;

use ethereum_types::U256;
use runtime::{Runtime, RuntimeContext};
use std::ffi::c_void;
use vm::{ActionParams, GasLeft, ReturnData};

use wasmer_runtime::{error, instantiate, memory, memory::MemoryView};

/// Wasmer runtime instance
pub struct WasmRuntime;

enum ExecutionOutcome {
	Suicide,
	Return,
	NotSpecial,
}

impl vm::Vm for WasmRuntime {
	fn exec(&mut self, params: ActionParams, ext: &mut vm::Ext) -> vm::Result<GasLeft> {
		let adjusted_gas = params.gas * U256::from(ext.schedule().wasm().opcodes_div)
			/ U256::from(ext.schedule().wasm().opcodes_mul);

		if adjusted_gas > ::std::u64::MAX.into() {
			return Err(vm::Error::Wasm(
				"Wasm runtime cannot run contracts with gas (wasm adjusted) >= 2^64".to_owned(),
			));
		}

		let (gas_left, result) = {
			// Explicitly split the input into code and data
			let (_module, code, data) = parser::payload(&params, ext.schedule().wasm())?;

			let mut runtime = Runtime::with_params(
				ext,
				adjusted_gas.low_u64(), // cannot overflow, checked above
				data.to_vec(),
				RuntimeContext {
					address: params.address,
					sender: params.sender,
					origin: params.origin,
					value: params.value.value(),
				},
			);

			let raw_ptr = &mut runtime as *mut _ as *mut c_void;
			let module = wasmer_runtime::compile(&code).unwrap();

			// Default memory descriptor
			let mut descriptor = wasmer_runtime::wasm::MemoryDescriptor {
				minimum: wasmer_runtime::units::Pages(0),
				maximum: Some(wasmer_runtime::units::Pages(0)),
				shared: false,
			};

			// Get memory descriptor from code import
			// TODO handle case if more than 1 present
			for (_index, (_import_object, expected_memory_desc)) in &module.info().imported_memories
			{
				descriptor = *expected_memory_desc;
			}

			let mem_obj = memory::Memory::new(descriptor).unwrap();
			let mem_view: MemoryView<u8> = mem_obj.view();
			let memory_size = mem_view.len() / 65535;
			let instance = module
				.instantiate(&runtime::imports::get_import_object(mem_obj, raw_ptr))
				.unwrap();

			// cannot overflow if static_region < 2^16,
			// initial_memory ∈ [0..2^32))
			// total_charge <- static_region * 2^32 * 2^16
			// total_charge ∈ [0..2^64) if static_region ∈ [0..2^16)
			// qed

			assert!(runtime.schedule().wasm().initial_mem_cost < 1 << 16);
			runtime.charge(|s| memory_size as u64 * s.wasm().initial_mem_cost as u64);

			let invoke_result = instance.call("call", &[]);
			let mut execution_outcome = ExecutionOutcome::NotSpecial;
			if let Err(wasmer_runtime::error::CallError::Runtime(ref trap)) = invoke_result {
				if let error::RuntimeError::Error { data } = trap {
					if let Some(runtime_err) = data.downcast_ref::<runtime::Error>() {
						// Expected errors thrown from runtime
						match runtime_err {
							runtime::Error::Suicide => {
								execution_outcome = ExecutionOutcome::Suicide;
							}
							runtime::Error::Return => {
								execution_outcome = ExecutionOutcome::Return;
							}
							_ => {}
						}
					}
				}
			}

			if let (ExecutionOutcome::NotSpecial, Err(e)) = (execution_outcome, invoke_result) {
				trace!(target: "wasm", "Error executing contract: {:?}", e);
				return Err(vm::Error::Wasm(format!("Wasm runtime error: {:?}", e)));
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

		if result.is_empty() {
			trace!(target: "wasm", "Contract execution result is empty.");
			Ok(GasLeft::Known(gas_left))
		} else {
			let len = result.len();
			Ok(GasLeft::NeedsReturn {
				gas_left: gas_left,
				data: ReturnData::new(result, 0, len),
				apply_state: true,
			})
		}
	}
}
