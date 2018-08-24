use ethereum_types::H256;
use vm::Result;

pub trait Storage {
	fn fetch_bytes(&self, key: &H256) -> Result<Vec<u8>>;
	fn store_bytes(&mut self, bytes: &[u8]) -> Result<H256>;
}

pub struct NullStorage;

impl NullStorage {
	pub fn new() -> Self {
		NullStorage {}
	}
}

impl Storage for NullStorage {
	fn fetch_bytes(&self, _key: &H256) -> Result<Vec<u8>> {
		unimplemented!();
	}

	fn store_bytes(&mut self, _bytes: &[u8]) -> Result<H256> {
		unimplemented!();
	}
}
