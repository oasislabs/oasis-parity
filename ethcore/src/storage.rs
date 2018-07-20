use ethereum_types::H256;

pub trait Storage {
	fn request_bytes(&mut self, key: H256) -> Option<Vec<u8>>;
	fn store_bytes(&mut self, key: H256, bytes: &[u8]);
}

pub struct DummyStorage {}

impl Storage for DummyStorage {
	fn request_bytes(&mut self, key: H256) -> Option<Vec<u8>> {
		unimplemented!();
	}

	fn store_bytes(&mut self, key: H256, bytes: &[u8]) {
		unimplemented!();
	}
}
