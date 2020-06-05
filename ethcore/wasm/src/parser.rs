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

//! ActionParams parser for wasm

use parity_wasm::elements::{self, Deserialize};
use parity_wasm::peek_size;
use vm;
use wasm_utils::{self, rules};
use std::io::Seek;

fn gas_rules(wasm_costs: &vm::WasmCosts) -> rules::Set {
	rules::Set::new(wasm_costs.regular, {
		let mut vals = ::std::collections::BTreeMap::new();
		vals.insert(
			rules::InstructionType::Load,
			rules::Metering::Fixed(wasm_costs.mem as u32),
		);
		vals.insert(
			rules::InstructionType::Store,
			rules::Metering::Fixed(wasm_costs.mem as u32),
		);
		vals.insert(
			rules::InstructionType::Div,
			rules::Metering::Fixed(wasm_costs.div as u32),
		);
		vals.insert(
			rules::InstructionType::Mul,
			rules::Metering::Fixed(wasm_costs.mul as u32),
		);
		vals
	})
	.with_grow_cost(wasm_costs.grow_mem)
	// enabling the following line disables floats
	//.with_forbidden_floats()
}

pub struct ParsedModule<'a> {
	pub module: elements::Module,
	pub code: &'a [u8],
	pub data: &'a [u8],
}

/// Splits payload to code and data according to params.params_type, also
/// loads the module instance from payload and injects gas counter according
/// to schedule.
pub fn payload<'a>(params: &'a vm::ActionParams) -> Result<ParsedModule<'a>, vm::Error> {
	let code = match params.code {
		Some(ref code) => &code[..],
		None => {
			return Err(vm::Error::Wasm("Invalid wasm call".to_owned()));
		}
	};

	info!("code is {} bytes long", code.len());
	let (mut cursor, data_position) = match params.params_type {
		vm::ParamsType::Embedded => {
			let module_size = peek_size(&*code);
			info!(
				"params.params_type is Embedded, module_size is {}",
				module_size
			);
			(::std::io::Cursor::new(&code[..module_size]), module_size + 2)
		}
		vm::ParamsType::Separate => {
			info!("params.params_type is Separate, all of code is the module");
			(::std::io::Cursor::new(&code[..code.len()-2]), 0)
		},
	};

	info!("Deserializing module: {:?}", cursor.to_owned());
	let deserialized_module = elements::Module::deserialize(&mut cursor)
		.map_err(|err| vm::Error::Wasm(format!("Error deserializing contract code ({:?})", err)))?;

	if deserialized_module
		.memory_section()
		.map_or(false, |ms| ms.entries().len() > 0)
	{
		// According to WebAssembly spec, internal memory is hidden from embedder and should not
		// be interacted with. So we disable this kind of modules at decoding level.
		return Err(vm::Error::Wasm(format!(
			"Malformed wasm module: internal memory"
		)));
	}

	let (code, data): (&[u8], &[u8]) = match params.params_type {
		vm::ParamsType::Embedded => {
			if data_position < code.len() {
				(&code[..cursor.stream_len()], &code[data_position..])
			} else {
				(&code[..cursor.stream_len()], &[])
			}
		}
		vm::ParamsType::Separate => (
			&code[..code.len()-2],
			match params.data {
				Some(ref s) => &s[..],
				None => &[],
			},
		),
	};

	Ok(ParsedModule {
		module: deserialized_module,
		code,
		data,
	})
}

pub fn inject_gas_counter_and_stack_limiter<'a>(
	module: elements::Module,
	wasm_costs: &vm::WasmCosts,
) -> Result<elements::Module, vm::Error> {
	let module = wasm_utils::inject_gas_counter(module, &gas_rules(wasm_costs))
		.map_err(|_| vm::Error::Wasm(format!("Wasm contract error: bytecode invalid")))?;
	let module = wasm_utils::stack_height::inject_limiter(module, wasm_costs.max_stack_height)
		.map_err(|_| vm::Error::Wasm(format!("Wasm contract error: stack limiter failure")))?;
	Ok(module)
}
