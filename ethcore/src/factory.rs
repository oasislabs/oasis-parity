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

use trie::TrieFactory;
use account_db::Factory as AccountFactory;
use evm::{Factory as EvmFactory, VMType};
use vm::{Vm, ActionParams, Schedule};
use wasm::WasmInterpreter;

const WASM_MAGIC_NUMBER: &'static [u8; 4] = b"\0asm";

/// Virtual machine factory
#[derive(Default, Clone)]
pub struct VmFactory {
	evm: EvmFactory,
}

impl VmFactory {
	pub fn create(&self, params: &ActionParams, schedule: &Schedule) -> Box<Vm> {
		if schedule.wasm.is_some() && params.code.as_ref().map_or(false, |code| code.len() > 4 && &code[0..4] == WASM_MAGIC_NUMBER) {
			println!("Creating wasm VM");
			Box::new(WasmInterpreter)
		} else {
			println!("Creating non-wasm VM");
			self.evm.create(&params.gas)
		}
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
