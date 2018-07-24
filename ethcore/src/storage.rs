use ethereum_types::H256;

pub trait Storage {
	fn request_bytes(&mut self, key: H256) -> Result<Vec<u8>, String>;
	fn store_bytes(&mut self, key: H256, bytes: &[u8]) -> Result<(), String>;
}

pub struct DummyStorage {}

impl Storage for DummyStorage {
	fn request_bytes(&mut self, _key: H256) -> Result<Vec<u8>, String> {
		unimplemented!();
	}

	fn store_bytes(&mut self, _key: H256, _bytes: &[u8]) -> Result<(), String> {
		unimplemented!();
	}
}
