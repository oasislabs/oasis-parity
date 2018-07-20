pub trait Storage {
	fn request_bytes(&mut self, key: &[u8]) -> Option<Vec<u8>>;
}

pub struct DummyStorage {}

impl Storage for DummyStorage {
	fn request_bytes(&mut self, key: &[u8]) -> Option<Vec<u8>> {
		unimplemented!();
	}
}
