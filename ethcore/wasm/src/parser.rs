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

/// Returns the first location in `haystack` at which `needle` appears as a subsequence.
fn index_of(haystack: &[u8], needle: &[u8]) -> Option<usize> {
	haystack
		.windows(needle.len())
		.position(|window| window == needle)
}

/// The magic separator string that callers are encouraged to provide in the payload (code || separator || data).
/// It is also a valid WASM section:
///   - 00 = section ID for "custom section"
///   - 19 = section length
///   - 18 = name length
///   - the rest is the section name, followed by 0 bytes of contents
///  This way, old versions of the runtime can parse and effectively ignore the separator.
const wasm_separator: &[u8] = b"\x00\x19\x18==OasisEndOfWasmMarker==";

/// Splits payload to code and data according to params.params_type, also
/// loads the module instance from payload and injects gas counter according
/// to schedule.
pub fn payload<'a>(params: &'a vm::ActionParams) -> Result<ParsedModule<'a>, vm::Error> {
	let payload = match params.code {
		Some(ref code) => &code[..],
		None => {
			return Err(vm::Error::Wasm(
				"Invalid wasm call; no params.code provided".to_owned(),
			));
		}
	};

	let (mut code, embedded_data) = match params.params_type {
		vm::ParamsType::Embedded => match index_of(payload, wasm_separator) {
			Some(separator_idx) => (
				::std::io::Cursor::new(&payload[..separator_idx]),
				&payload[separator_idx + wasm_separator.len()..],
			),
			None => {
				let module_size = peek_size(&*payload);
				(
					::std::io::Cursor::new(&payload[..module_size]),
					&payload[module_size..],
				)
			}
		},
		vm::ParamsType::Separate => (::std::io::Cursor::new(&payload[..]), &[] as &[u8]),
	};

	let mut deserialized_module = elements::Module::deserialize(&mut code)
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
		vm::ParamsType::Embedded => (code.into_inner(), embedded_data),
		vm::ParamsType::Separate => (
			code.into_inner(),
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

#[cfg(test)]
mod tests {
	use super::*;

	static simple_wasm: &[u8] = include_bytes!("../../res/wasi-tests/target/service/empty.wasm");

	#[test]
	fn uses_wasm_separator() {
		// This data is also a syntactically valid WASM section (0="type: custom section", 2=length, 42 42=data),
		// as is the wasm separator above. If the parser does not explicitly search for the separator, it will
		// gobble up `wasm_separator` and `data` as parts of WASM.
		let data: &[u8] = &[0, 2, 42, 42];

		let mut params = vm::ActionParams::default();
		params.code = Some(std::sync::Arc::new(
			[&simple_wasm[..], wasm_separator, data].concat(),
		));
		params.params_type = vm::ParamsType::Embedded;

		let parsed = payload(&params).unwrap();
		assert_eq!(parsed.code, &simple_wasm[..]);
		assert_eq!(parsed.data, data);
	}

	#[test]
	fn splits_wasm_without_separator() {
		let data: &[u8] = &[10, 20, 30, 40];

		let mut params = vm::ActionParams::default();
		params.code = Some(std::sync::Arc::new([&simple_wasm[..], data].concat()));
		params.params_type = vm::ParamsType::Embedded;

		// No WASM separator is present in the payload, but `data` does not start a syntactically valid WASM section,
		// (10=(some legal section type), 20=length longer than remaining bytes), so heuristics should stop parsing
		// the WASM there and still correctly split off data from code.
		let parsed = payload(&params).unwrap();
		assert_eq!(parsed.code, &simple_wasm[..]);
		assert_eq!(parsed.data, data);
	}

	#[test]
	fn fails_to_split_ambiguous_payload() {
		let data: &[u8] = &[1, 2, 3, 4, 5];

		let mut params = vm::ActionParams::default();
		params.code = Some(std::sync::Arc::new([&simple_wasm[..], data].concat()));
		params.params_type = vm::ParamsType::Embedded;

		// The first four bytes of `data` can be interpreted as either a WASM section or as data. We expect the parser
		// to do the former, and error out because the semantics of this fake WASM section are invalid.
		// THIS TEST ONLY ENCODES/DOCUMENTS A BUG. It is not important to preserve this behavior.
		assert_eq!(payload(&params).is_err(), true);
	}

	#[test]
	fn error_on_missing_wasm() {
		let mut params = vm::ActionParams::default();
		params.code = None;
		params.params_type = vm::ParamsType::Embedded;

		assert_eq!(payload(&params).is_err(), true);
	}

	#[test]
	fn error_on_memory_section() {
		let memory_section: &[u8] = &[5, 0]; // ID 5 (= WASM memory section); length 0

		let mut params = vm::ActionParams::default();
		params.code = Some(std::sync::Arc::new(
			[&simple_wasm[..], memory_section].concat(),
		));

		// WASMs are not allowed to have a memory section. Expect parser to error out.
		assert_eq!(payload(&params).is_err(), true);
	}
}
