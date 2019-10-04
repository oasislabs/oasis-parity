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

//! Env module glue for wasmi interpreter

use std::cell::RefCell;
use wasmi::{self, memory_units, Error, FuncInstance, FuncRef, MemoryInstance, MemoryRef};

pub struct StaticSignature(
	pub &'static [wasmi::ValueType],
	pub Option<wasmi::ValueType>,
);

impl Into<wasmi::Signature> for StaticSignature {
	fn into(self) -> wasmi::Signature {
		wasmi::Signature::new(self.0, self.1)
	}
}

pub(crate) fn host(signature: StaticSignature, idx: usize) -> FuncRef {
	FuncInstance::alloc_host(signature.into(), idx)
}

/// Import resolver for wasmi
/// Maps all functions that runtime support to the corresponding contract import
/// entries.
/// Also manages initial memory request from the runtime.
#[derive(Default)]
pub struct ImportResolver {
	pub(crate) max_memory: u32,
	pub(crate) memory: RefCell<Option<MemoryRef>>,
}

impl ImportResolver {
	/// New import resolver with specifed maximum amount of inital memory (in wasm pages = 64kb)
	pub fn with_limit(max_memory: u32) -> ImportResolver {
		ImportResolver {
			max_memory,
			memory: RefCell::new(None),
		}
	}

	/// Returns memory that was instantiated during the contract module
	/// start. If contract does not use memory at all, the dummy memory of length (0, 0)
	/// will be created instead. So this method always returns memory instance
	/// unless errored.
	pub fn memory_ref(&self) -> MemoryRef {
		{
			let mut mem_ref = self.memory.borrow_mut();
			if mem_ref.is_none() {
				*mem_ref = Some(
					MemoryInstance::alloc(memory_units::Pages(0), Some(memory_units::Pages(0)))
						.expect("Memory allocation (0, 0) should not fail; qed"),
				);
			}
		}

		self.memory
			.borrow()
			.clone()
			.expect("it is either existed or was created as (0, 0) above; qed")
	}

	/// Returns memory size module initially requested
	pub fn memory_size(&self) -> Result<u32, Error> {
		Ok(self.memory_ref().current_size().0 as u32)
	}
}
