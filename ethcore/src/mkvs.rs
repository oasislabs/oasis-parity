//! MKVS trait.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Merklized key-value store.
pub trait MKVS {
	/// Fetch entry with given key.
	fn get(&self, key: &[u8]) -> Option<Vec<u8>>;

	/// Update entry with given key.
	///
	/// If the database did not have this key present, [`None`] is returned.
	///
	/// If the database did have this key present, the value is updated, and the old value is
	/// returned.
	///
	/// [`None`]: std::option::Option
	fn insert(&mut self, key: &[u8], value: &[u8]) -> Option<Vec<u8>>;

	/// Remove entry with given key, returning the value at the key if the key was previously
	/// in the database.
	fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>>;

	/// Clone the MKVS.
	fn boxed_clone(&self) -> Box<MKVS>;
}

impl<T: ?Sized + MKVS> MKVS for Box<T> {
	fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
		MKVS::get(&**self, key)
	}

	fn insert(&mut self, key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
		MKVS::insert(&mut **self, key, value)
	}

	fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
		MKVS::remove(&mut **self, key)
	}

	fn boxed_clone(&self) -> Box<MKVS> {
		MKVS::boxed_clone(&**self)
	}
}

pub struct PrefixedMKVS<'a> {
	mkvs: &'a mut MKVS,
	prefix: &'a [u8],
}

impl<'a> PrefixedMKVS<'a> {
	pub fn new(mkvs: &'a mut MKVS, prefix: &'a [u8]) -> Self {
		Self { mkvs, prefix }
	}

	fn derive_key(&self, key: &[u8]) -> Vec<u8> {
		let mut output = self.prefix.to_vec();
		output.extend_from_slice(key);
		output
	}
}

impl<'a> MKVS for PrefixedMKVS<'a> {
	fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
		// Prevent access to the prefix key itself.
		if key.is_empty() {
			return None;
		}

		let key = self.derive_key(key);
		self.mkvs.get(&key)
	}

	fn insert(&mut self, key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
		// Prevent overwrite of the prefix key itself.
		if key.is_empty() {
			return None;
		}

		let key = self.derive_key(key);
		self.mkvs.insert(&key, value)
	}

	fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
		// Prevent overwrite of the prefix key itself.
		if key.is_empty() {
			return None;
		}

		let key = self.derive_key(key);
		self.mkvs.remove(&key)
	}

	fn boxed_clone(&self) -> Box<MKVS> {
		self.mkvs.boxed_clone()
	}
}

pub struct ReadOnlyPrefixedMKVS<'a> {
	mkvs: &'a MKVS,
	prefix: &'a [u8],
}

impl<'a> ReadOnlyPrefixedMKVS<'a> {
	pub fn new(mkvs: &'a MKVS, prefix: &'a [u8]) -> Self {
		Self { mkvs, prefix }
	}

	fn derive_key(&self, key: &[u8]) -> Vec<u8> {
		let mut output = self.prefix.to_vec();
		output.extend_from_slice(key);
		output
	}
}

impl<'a> MKVS for ReadOnlyPrefixedMKVS<'a> {
	fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
		// Prevent access to the prefix key itself.
		if key.is_empty() {
			return None;
		}

		let key = self.derive_key(key);
		self.mkvs.get(&key)
	}

	fn insert(&mut self, key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
		unimplemented!("MKVS is read-only");
	}

	fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
		unimplemented!("MKVS is read-only");
	}

	fn boxed_clone(&self) -> Box<MKVS> {
		self.mkvs.boxed_clone()
	}
}

#[derive(Clone)]
pub struct MemoryMKVS(Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>);

impl MemoryMKVS {
	pub fn new() -> Self {
		MemoryMKVS(Arc::new(Mutex::new(HashMap::new())))
	}
}

impl MKVS for MemoryMKVS {
	fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
		self.0.lock().unwrap().get(key).map(|v| v.clone())
	}

	fn insert(&mut self, key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
		self.0
			.lock()
			.unwrap()
			.insert(key.to_vec(), value.to_vec())
			.map(|v| v.clone())
	}

	fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
		self.0.lock().unwrap().remove(key).map(|v| v.clone())
	}

	fn boxed_clone(&self) -> Box<MKVS> {
		Box::new(self.clone())
	}
}
