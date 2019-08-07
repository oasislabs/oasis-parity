// (c) Oasis Labs.  All right reserved.
// This file is part of Parity.
//
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

//! Counting Tracer
//!
//! This externalities tracer is used to estimate the size of read- / write-conflict sets.  It
//! implements the ExtTracer interface to count the number of unique persistent storage read
//! and write locations.

// We may want to put locations into equivalence sets, e.g., by masking off the low order 10 or
// so bits of an address.  This would effectively treat elements of an array as equivalent from
// the viewpoint of conflict set analysis, and would also reduce the size of the conflict sets
// at the cost of decreased analysis precision and therefore reduced parallelism.

use std::convert::Into;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::vec;

use ethereum_types::{Address, H256, U256};

use trace_ext::bloomfilter::BloomFilter;
use trace_ext::ext_tracer::ExtTracer;

struct GlobalPersistentLocation {
	contract: Address,
	location: H256,
}

// We need to be able to reimplement, in golang, the same hash function so that a serialized
// representation of the Bloom filter can be meaningfully transferred.  This is required in
// order for the transaction scheduler to work with the data generated here in Rust.  We
// explicitly write the hash order for the struct to be in declaration order, in case the Rust
// compiler is allowed to change how hashing structs is implemented.  See bloomfilter.rs -- we
// use SipHash as the underlying hash primitive.
impl Hash for GlobalPersistentLocation {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.contract.hash(state);
		self.location.hash(state);
	}
}

struct ConflictSet {
	// When the item count gets too large, the Bloom filter will generate false positives
	// and if in such a scenario we used the BloomFilter::check to prevent adding to a
	// counter, for example, we would incorrectly not count that access believing that it
	// is a previously-seen location.
	read_set: BloomFilter,
	read_count: u64,
	write_set: BloomFilter,
	write_count: u64,
}

impl ConflictSet {
	/// Create a new ConflictSet with the given expected size, false-positive rate, etc.
	fn new(expected_item_count: usize, false_positive_prob: f64) -> Self {
		Self {
			read_set: BloomFilter::new_for_fp_rate(expected_item_count, false_positive_prob),
			read_count: 0,
			write_set: BloomFilter::new_for_fp_rate(expected_item_count, false_positive_prob),
			write_count: 0,
		}
	}

	fn add_to_set(set: &mut BloomFilter, ctr: &mut u64, contract: &Address, key: &H256) {
		let obj = GlobalPersistentLocation {
			contract: *contract,
			location: *key,
		};
		if !set.check(&obj) {
			*ctr += 1;
			set.set(&obj);
		}
	}

	/// Add the given contract address and persistent location address to the read set.
	fn add_read(&mut self, contract: &Address, key: &H256) {
		ConflictSet::add_to_set(&mut self.read_set, &mut self.read_count, contract, key);
	}

	/// Add the given contract address and persistent location address to the write set.
	fn add_write(&mut self, contract: &Address, key: &H256) {
		ConflictSet::add_to_set(&mut self.write_set, &mut self.write_count, contract, key);
	}

	fn get_rw_counts(&self) -> (u64, u64) {
		(self.read_count, self.write_count)
	}
}

/// An ExtTracer that counts read and write addresses used to get (approximate) conflict set
/// sizes.
pub struct CountingTracer {
	contract: Address,
	trace: Arc<Mutex<ConflictSet>>,
}

const FP_RATE: f64 = 0.01; // 1% false positive rate.
const EXPECTED_ITEM_COUNT: usize = 10000; // Will we want to have several sizes?

impl CountingTracer {
	pub fn new() -> Self {
		CountingTracer::new_extended(EXPECTED_ITEM_COUNT, FP_RATE)
	}

	pub fn new_extended(expected_item_count: usize, false_positive_rate: f64) -> Self {
		Self {
			contract: Address::zero(),
			trace: Arc::new(Mutex::new(ConflictSet::new(
				expected_item_count,
				false_positive_rate,
			))),
		}
	}

	// new_subtracer
	pub fn new_subtracer(&self, contract: &Address) -> Self {
		Self {
			contract: *contract,
			trace: self.trace.clone(),
		}
	}

	pub fn get_rw_counts(&self) -> (u64, u64) {
		let cs = self.trace.lock().unwrap();
		cs.get_rw_counts()
	}
}

impl ExtTracer for CountingTracer {
	fn trace_storage_at(&self, key: &H256) {
		let mut trace = self.trace.lock().unwrap();

		trace.add_read(&self.contract, key);
	}

	/// Transaction execution writes into persistent state.
	fn trace_set_storage(&self, key: &H256) {
		let mut trace = self.trace.lock().unwrap();

		trace.add_write(&self.contract, key);
	}

	/// Transaction (indirectly) performs an exists query.
	fn trace_exists(&self, address: &Address) {}

	/// Transactions (indirectly) performs an exists_and_not_null query.
	fn trace_exists_and_not_null(&self, address: &Address) {}

	/// Transaction performs an origin_balance or balance query.  Unlike Ext, we do not know
	/// origin address, so it must be provided by Ext implementations.
	fn trace_balance(&self, origin_address: &Address) {}

	/// subtracer returns an Ext tracer for use for the context of the sub-transaction call.
	fn subtracer(&mut self, code_address: &Address) -> Self {
		self.new_subtracer(code_address)
	}
}

#[test]
fn test_count() {
	let mut ct = CountingTracer::new(); // with defaults
	{
		// lifetime of st
		let mut st = ct.subtracer(&Address::from("cd1722f3947def4cf144679da39c4c32bdc35681"));
		st.trace_storage_at(&H256::from(&U256::zero()));
		st.trace_storage_at(&H256::from(&U256::from(1)));
		st.trace_set_storage(&H256::from(&U256::zero()));
		// subcontract invocation
		{
			// lifetime of st2
			let mut st2 = st.subtracer(&Address::from("0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6"));
			st2.trace_storage_at(&H256::from(&U256::zero()));
			st2.trace_storage_at(&H256::from(&U256::from(1)));
			st2.trace_set_storage(&H256::from(&U256::zero()));
		}
	}

	let expected_trace = (4, 2);
	assert_eq!(ct.get_rw_counts(), expected_trace);
}
