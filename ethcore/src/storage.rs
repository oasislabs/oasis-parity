use ethereum_types::H256;
use vm::Result;

pub trait Storage {
	fn request_bytes(&mut self, key: H256) -> Result<Vec<u8>>;
	fn store_bytes(&mut self, bytes: &[u8]) -> Result<H256>;
}

pub struct NullStorage;

impl NullStorage {
	pub fn new() -> Self {
		NullStorage {}
	}
}

impl Storage for NullStorage {
	fn request_bytes(&mut self, _key: H256) -> Result<Vec<u8>> {
		unimplemented!();
	}

	fn store_bytes(&mut self, _bytes: &[u8]) -> Result<H256> {
		unimplemented!();
	}
}
