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

//! Ethereum virtual machine.

extern crate bit_set;
extern crate ethereum_types;
extern crate heapsize;
extern crate keccak_hash as hash;
extern crate memory_cache;
extern crate vm;

#[macro_use]
extern crate lazy_static;

#[cfg_attr(feature = "evm-debug", macro_use)]
extern crate log;

#[cfg(test)]
extern crate rustc_hex;

pub mod evm;
pub mod interpreter;

#[macro_use]
pub mod factory;
mod instructions;
mod vmtype;

#[cfg(all(feature = "benches", test))]
mod benches;
#[cfg(test)]
mod tests;

pub use self::evm::{CostType, FinalizationResult, Finalize};
pub use self::factory::Factory;
pub use self::instructions::{push_bytes, InstructionInfo, INSTRUCTIONS};
pub use self::vmtype::VMType;
pub use vm::{
	ActionParams, CallType, CleanDustMode, ContractCreateResult, CreateContractAddress, EnvInfo,
	Ext, GasLeft, MessageCallResult, ReturnData, Schedule,
};
