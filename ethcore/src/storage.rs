use ethereum_types::H256;
use vm::Result;

pub trait Storage: Send + Sync {
	fn request_bytes(&mut self, key: H256) -> Result<Vec<u8>>;
	fn store_bytes(&mut self, bytes: &[u8]) -> Result<H256>;
}

pub struct DummyStorage {}

impl DummyStorage {
	pub fn new() -> Self {
		DummyStorage {}
	}
}

impl Storage for DummyStorage {
	fn request_bytes(&mut self, _key: H256) -> Result<Vec<u8>> {
		unimplemented!();
	}

	fn store_bytes(&mut self, _bytes: &[u8]) -> Result<H256> {
		unimplemented!();
	}
}
