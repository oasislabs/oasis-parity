// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

use trie::TrieFactory;
use account_db::Factory as AccountFactory;
use confidential_vm::ConfidentialVm;
use evm::{Factory as EvmFactory, VMType};
use vm::{Vm, ActionParams, Schedule};
use wasm::WasmInterpreter;
use bytes::Bytes;

const WASM_MAGIC_NUMBER: &'static [u8; 4] = b"\0asm";

/// Virtual machine factory
#[derive(Default, Clone)]
pub struct VmFactory {
	evm: EvmFactory,
}

impl VmFactory {
	pub fn create(&self, params: &ActionParams, schedule: &Schedule) -> Box<Vm> {
		let mut vm = self._create(params, schedule);
		if params.confidential {
			Box::new(ConfidentialVm::new(vm))
		} else {
			vm
		}
	}

	fn _create(&self, params: &ActionParams, schedule: &Schedule) -> Box<Vm> {
		let raw_code = Self::raw_code(params);
		if schedule.wasm.is_some() && raw_code.len() > 4 && &raw_code[0..4] == WASM_MAGIC_NUMBER {
			Box::new(WasmInterpreter)
		} else {
			self.evm.create(&params.gas)
		}
	}

	/// Removes the confidential prefix from the ActionParams' code, if needed.
	fn raw_code(params: &ActionParams) -> Bytes {
		params.code.as_ref().map_or(vec![], |code| {
			if params.confidential {
				ConfidentialVm::remove_prefix(code.to_vec())
			} else {
				code.to_vec()
			}
		})
	}

	pub fn new(evm: VMType, cache_size: usize) -> Self {
		VmFactory { evm: EvmFactory::new(evm, cache_size) }
	}
}

impl From<EvmFactory> for VmFactory {
	fn from(evm: EvmFactory) -> Self {
		VmFactory { evm: evm }
	}
}

/// Collection of factories.
#[derive(Default, Clone)]
pub struct Factories {
	/// factory for evm.
	pub vm: VmFactory,
	/// factory for tries.
	pub trie: TrieFactory,
	/// factory for account databases.
	pub accountdb: AccountFactory,
}
