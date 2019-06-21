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

//! Virtual machines support library

#[macro_use]
extern crate log;
extern crate byteorder;
extern crate common_types as types;
extern crate ethcore_bytes as bytes;
extern crate ethereum_types;
extern crate ethjson;
extern crate keccak_hash as hash;
extern crate patricia_trie as trie;
extern crate rlp;
extern crate serde;
#[macro_use]
extern crate serde_json;

#[cfg(test)]
extern crate elastic_array;

mod action_params;
mod call_type;
mod env_info;
mod error;
mod ext;
mod oasis_contract;
mod oasis_vm;
mod return_data;
mod schedule;

pub mod tests;

pub use action_params::{ActionParams, ActionValue, ParamsType};
pub use call_type::CallType;
pub use env_info::{EnvInfo, LastHashes};
pub use error::{Error, Result};
pub use ext::{ContractCreateResult, CreateContractAddress, Ext, MessageCallResult};
pub use oasis_contract::{OasisContract, OASIS_HEADER_PREFIX};
pub use oasis_vm::{ConfidentialCtx, OasisVm};
pub use return_data::{GasLeft, ReturnData};
pub use schedule::{CleanDustMode, Schedule, WasmCosts};

/// Virtual Machine interface
pub trait Vm {
	/// This function should be used to execute transaction.
	/// It returns either an error, a known amount of gas left, or parameters to be used
	/// to compute the final gas left.
	fn exec(&mut self, params: ActionParams, ext: &mut Ext) -> Result<GasLeft>;

	fn prepare(&mut self, params: ActionParams) -> Result<()>;

}
