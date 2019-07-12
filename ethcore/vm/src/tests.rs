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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use bytes::Bytes;
use ethereum_types::{Address, H256, U256};
use {
	CallType, ContractCreateResult, CreateContractAddress, EnvInfo, Ext, GasLeft,
	MessageCallResult, Result, ReturnData, Schedule,
};

pub struct FakeLogEntry {
	pub topics: Vec<H256>,
	pub data: Bytes,
}

#[derive(PartialEq, Eq, Hash, Debug)]
pub enum FakeCallType {
	Call,
	Create,
}

#[derive(PartialEq, Eq, Hash, Debug)]
pub struct FakeCall {
	pub call_type: FakeCallType,
	pub gas: U256,
	pub sender_address: Option<Address>,
	pub receive_address: Option<Address>,
	pub value: Option<U256>,
	pub data: Bytes,
	pub code_address: Option<Address>,
}

/// Fake externalities test structure.
///
/// Can't do recursive calls.
#[derive(Default)]
pub struct FakeExt {
	pub store: HashMap<Vec<u8>, Vec<u8>>,
	pub suicides: HashSet<Address>,
	pub calls: HashSet<FakeCall>,
	pub sstore_clears: usize,
	pub depth: usize,
	pub blockhashes: HashMap<U256, H256>,
	pub codes: HashMap<Address, Arc<Bytes>>,
	pub logs: Vec<FakeLogEntry>,
	pub info: EnvInfo,
	pub schedule: Schedule,
	pub balances: HashMap<Address, U256>,
	pub tracing: bool,
	pub is_static: bool,
	pub is_create: bool,
}

// similar to the normal `finalize` function, but ignoring NeedsReturn.
pub fn test_finalize(res: Result<GasLeft>) -> Result<U256> {
	match res {
		Ok(GasLeft::Known(gas)) => Ok(gas),
		Ok(GasLeft::NeedsReturn { .. }) => unimplemented!(), // since ret is unimplemented.
		Err(e) => Err(e),
	}
}

impl FakeExt {
	/// New fake externalities
	pub fn new() -> Self {
		let mut this = FakeExt::default();
		this.info.last_hashes = Arc::new(vec![H256::zero()]);
		this
	}

	/// New fake externalities with byzantium schedule rules
	pub fn new_byzantium() -> Self {
		let mut ext = FakeExt::default();
		ext.schedule = Schedule::new_byzantium();
		ext
	}

	/// New fake externalities with constantinople schedule rules
	pub fn new_constantinople() -> Self {
		let mut ext = FakeExt::default();
		ext.schedule = Schedule::new_constantinople();
		ext
	}

	/// Alter fake externalities to allow wasm
	pub fn with_wasm(mut self) -> Self {
		self.schedule.wasm = Some(Default::default());
		self
	}

	fn bytes2hash<B: AsRef<[u8]>>(bytes: B) -> H256 {
		let bytes = bytes.as_ref();
		let mut h = [0u8; 32];
		let len = std::cmp::min(h.len(), bytes.len());
		h[..len].copy_from_slice(&bytes[..len]);
		H256::from(h)
	}
}

impl Ext for FakeExt {
	fn storage_at(&self, key: &H256) -> Result<H256> {
		let key: &[u8] = key.as_ref();
		Ok(self
			.store
			.get(key)
			.map(Self::bytes2hash)
			.unwrap_or_default())
	}

	fn set_storage(&mut self, key: H256, value: H256) -> Result<()> {
		self.store.insert(key.to_vec(), value.to_vec());
		Ok(())
	}

	fn storage_bytes_at(&self, key: &H256) -> Result<Vec<u8>> {
		Ok(Vec::new())
	}

	fn storage_bytes_len(&self, key: &H256) -> Result<u64> {
		Ok(0)
	}

	fn set_storage_bytes(&mut self, key: H256, value: Vec<u8>) -> Result<()> {
		Ok(())
	}

	fn storage_expiry(&self, address: &Address) -> Result<u64> {
		Ok(u64::max_value())
	}

	fn seconds_until_expiry(&self) -> Result<u64> {
		Ok(42)
	}

	fn exists(&self, address: &Address) -> Result<bool> {
		Ok(self.balances.contains_key(address))
	}

	fn exists_and_not_null(&self, address: &Address) -> Result<bool> {
		Ok(self.balances.get(address).map_or(false, |b| !b.is_zero()))
	}

	fn origin_balance(&self) -> Result<U256> {
		unimplemented!()
	}

	fn origin_nonce(&self) -> U256 {
		U256::zero()
	}

	fn balance(&self, address: &Address) -> Result<U256> {
		Ok(self.balances[address])
	}

	fn blockhash(&mut self, number: &U256) -> H256 {
		self.blockhashes.get(number).unwrap_or(&H256::new()).clone()
	}

	fn create(
		&mut self,
		gas: &U256,
		value: &U256,
		code: &[u8],
		_address: CreateContractAddress,
	) -> ContractCreateResult {
		self.calls.insert(FakeCall {
			call_type: FakeCallType::Create,
			gas: *gas,
			sender_address: None,
			receive_address: None,
			value: Some(*value),
			data: code.to_vec(),
			code_address: None,
		});
		ContractCreateResult::Failed
	}

	fn call(
		&mut self,
		gas: &U256,
		sender_address: &Address,
		receive_address: &Address,
		value: Option<U256>,
		data: &[u8],
		code_address: &Address,
		_output: &mut [u8],
		_call_type: CallType,
	) -> MessageCallResult {
		self.calls.insert(FakeCall {
			call_type: FakeCallType::Call,
			gas: *gas,
			sender_address: Some(sender_address.clone()),
			receive_address: Some(receive_address.clone()),
			value: value,
			data: data.to_vec(),
			code_address: Some(code_address.clone()),
		});
		MessageCallResult::Success(*gas, ReturnData::empty())
	}

	fn extcode(&self, address: &Address) -> Result<Arc<Bytes>> {
		Ok(self
			.codes
			.get(address)
			.unwrap_or(&Arc::new(Bytes::new()))
			.clone())
	}

	fn extcodesize(&self, address: &Address) -> Result<usize> {
		Ok(self.codes.get(address).map_or(0, |c| c.len()))
	}

	fn log(&mut self, topics: Vec<H256>, data: &[u8]) -> Result<()> {
		self.logs.push(FakeLogEntry {
			topics: topics,
			data: data.to_vec(),
		});
		Ok(())
	}

	fn ret(self, _gas: &U256, _data: &ReturnData, _apply_state: bool) -> Result<U256> {
		unimplemented!();
	}

	fn suicide(&mut self, refund_address: &Address) -> Result<()> {
		self.suicides.insert(refund_address.clone());
		Ok(())
	}

	fn schedule(&self) -> &Schedule {
		&self.schedule
	}

	fn env_info(&self) -> &EnvInfo {
		&self.info
	}

	fn depth(&self) -> usize {
		self.depth
	}

	fn is_static(&self) -> bool {
		self.is_static
	}

	fn is_create(&self) -> bool {
		self.is_create
	}

	fn inc_sstore_clears(&mut self, bytes_len: u64) -> Result<()> {
		self.sstore_clears += 1;
		Ok(())
	}

	fn trace_next_instruction(&mut self, _pc: usize, _instruction: u8, _gas: U256) -> bool {
		self.tracing
	}

	fn is_confidential_contract(&self, contract: &Address) -> Result<bool> {
		Ok(false)
	}

	fn as_kvstore(&self) -> &dyn blockchain_traits::KVStore {
		self
	}

	fn as_kvstore_mut(&mut self) -> &mut dyn blockchain_traits::KVStoreMut {
		self
	}
}

impl blockchain_traits::KVStore for FakeExt {
	fn contains(&self, key: &[u8]) -> bool {
		self.store.contains_key(key)
	}

	fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
		self.store.get(key).map(Vec::to_owned)
	}
}

impl blockchain_traits::KVStoreMut for FakeExt {
	fn set(&mut self, key: &[u8], value: &[u8]) {
		self.store.insert(key.to_vec(), value.to_vec());
	}

	fn remove(&mut self, key: &[u8]) {
		self.store.remove(key);
	}
}
