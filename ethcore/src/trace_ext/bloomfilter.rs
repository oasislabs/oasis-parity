// Copyright 2018 Oasis Labs.
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

/// Bloom filter
///
/// This bloom filter implementation is used by the externalities tracer to estimate the size
/// of read- / write-conflict sets.
// Some of this code is taken from util/bloom/src/lib.rs; to reduce memory usage, we do not
// keep a HashSet of all bit locations, since for long running transactions this could be
// large, and as long as we do not intend to serialize the Bloom filter the journal is not
// needed, and depending on filter saturation and cache behavior, it may be simpler to just
// iterate through the array containing the bitmap to implement the
// serialization/deserialization interface.  If/when we decide we want to have a Bloom filter
// that can be serialized, we can add that functionality back in.

// Given two Bloom filter bitmaps A and B of the same size, using the same set of hash
// functions, the bitmap formed by the bitwise intersection $A \wedge B$ is a bitmap that can
// be used to test membership in both Bloom filters simultaneously, and the Swamidass & Baldi
// approximation formula should yield the approximate number of elements common to both
// original Bloom filters.  The same consideration applies for union.  Intersection, union, and
// estimating number of entries are operations that we support.
extern crate siphasher;

use self::siphasher::sip::SipHasher;
use std::cmp;
use std::f64;
use std::hash::{Hash, Hasher};
use std::usize;

use trace_ext::error::Error;

struct Bitmap {
	elems: Vec<u64>,
}

impl Bitmap {
	pub fn new(size: usize) -> Self {
		let num_u64 = (size / 64) + if size % 64 != 0 { 1 } else { 0 };
		Self {
			elems: vec![0u64; num_u64],
		}
	}

	pub fn set(&mut self, index: usize) {
		let e_index = index / 64;
		let bit_index = index % 64;
		let val = self.elems.get_mut(e_index).unwrap();
		*val |= 1u64 << bit_index;
	}

	pub fn get(&self, index: usize) -> bool {
		let e_index = index / 64;
		let bit_index = index % 64;
		self.elems[e_index] & (1 << bit_index) != 0
	}

	/// pop_count is used for SwamidassBaldi approximation formula for the number of
	/// entries in a Bloom filter, and for saturation.
	pub fn pop_count(&self) -> usize {
		self.elems
			.iter()
			.fold(0usize, |acc, e| acc + e.count_ones() as usize)
	}

	/// Returns a new Bitmap that is the intersection of self and other.
	pub fn intersect(&self, other: &Self) -> Result<Self, Error> {
		// If this were done using C++ templates, the bitmap size would be a template
		// parameter and different sizes would be considered different types, so
		// intersection with a bitmap of a different size would be forbidden by the
		// type system.  This could be done in Rust if we defined a new type for each
		// bitmap size used.  Do we need compatibility with util::bloom?
		if self.elems.len() != other.elems.len() {
			return Err(Error::BitmapSizeMismatch);
		}
		let mut wedge = vec![0u64; self.elems.len()];
		for i in 0..self.elems.len() {
			wedge[i] = self.elems[i] & other.elems[i];
		}
		Ok(Self { elems: wedge })
	}

	/// Returns a new Bitmap that is the union of self and other.
	pub fn union(&self, other: &Self) -> Result<Self, Error> {
		if self.elems.len() != other.elems.len() {
			return Err(Error::BitmapSizeMismatch);
		}
		let mut vee = vec![0u64; self.elems.len()];
		for i in 0..self.elems.len() {
			vee[i] = self.elems[i] | other.elems[i];
		}
		Ok(Self { elems: vee })
	}
}

pub struct BloomFilter {
	bitmap: Bitmap,
	bitmap_bits: u64,
	k_num: u32,
}

impl BloomFilter {
	pub fn new(bitmap_size_bytes: usize, items_count: usize) -> Self {
		assert!(bitmap_size_bytes > 0);
		assert!(items_count > 0);
		assert!(bitmap_size_bytes <= usize::MAX / 8);
		let bitmap_bits = (bitmap_size_bytes * 8) as u64;
		let k_num = BloomFilter::optimal_k_num(bitmap_bits, items_count);
		Self {
			bitmap: Bitmap::new(bitmap_bits as usize),
			bitmap_bits,
			k_num,
		}
	}

	/// Create a new bloom filter structure.
	/// items_count is an estimation of the maximum number of items to store.
	/// fp_p is the wanted rate of false positives, in ]0.0, 1.0[
	pub fn new_for_fp_rate(items_count: usize, fp_p: f64) -> Self {
		let bitmap_size = BloomFilter::compute_bitmap_size(items_count, fp_p);
		BloomFilter::new(bitmap_size, items_count)
	}

	/// Compute a recommended bitmap size for items_count items
	/// and a fp_p rate of false positives.
	/// fp_p obviously has to be within the ]0.0, 1.0[ range.
	pub fn compute_bitmap_size(items_count: usize, fp_p: f64) -> usize {
		assert!(items_count > 0);
		assert!(fp_p > 0.0 && fp_p < 1.0);
		let log2 = f64::consts::LN_2;
		let log2_2 = log2 * log2;
		((items_count as f64) * f64::ln(fp_p) / (-8.0 * log2_2)).ceil() as usize
	}

	/// Records the presence of an item.
	pub fn set<T>(&mut self, item: &T)
	where
		T: Hash,
	{
		let base_hash = BloomFilter::sip_hash(item);
		for k_i in 0..self.k_num {
			let bit_offset = (BloomFilter::bloom_hash(base_hash, k_i) % self.bitmap_bits) as usize;
			self.bitmap.set(bit_offset);
		}
	}

	/// Check if an item is present in the set.  There can be false positives, but no false
	/// negatives.
	pub fn check<T>(&self, item: &T) -> bool
	where
		T: Hash,
	{
		let base_hash = BloomFilter::sip_hash(item);
		for k_i in 0..self.k_num {
			let bit_offset = (BloomFilter::bloom_hash(base_hash, k_i) % self.bitmap_bits) as usize;
			if !self.bitmap.get(bit_offset) {
				return false;
			}
		}
		true
	}

	/// Return the number of bits in the filter
	pub fn number_of_bits(&self) -> u64 {
		self.bitmap_bits
	}

	/// Return the number of hash functions used for `check` and `set`
	pub fn number_of_hash_functions(&self) -> u32 {
		self.k_num
	}

	/// Return the number of set bits in the filter
	pub fn pop_count(&self) -> u64 {
		self.bitmap.pop_count() as u64
	}

	pub fn saturation(&self) -> f64 {
		(self.bitmap.pop_count() as f64) / (self.bitmap_bits as f64)
	}

	/// Return the estimated number of entries in the filter
	pub fn est_num_entries(&self) -> u64 {
		// Swamidass & Baldi's estimation (paywalled:
		// https://pubs.acs.org/doi/full/10.1021/ci600526a):
		//
		// n* = -\frac{m}{k}\ln{1 - \frac{X}{m}}
		//
		// where n* is the estimated number of entries, m is the length of the filter,
		// k is the number of hash functions, and X is the number of bits set to one.
		let f_m = self.number_of_bits() as f64;
		let fest = -f_m / f64::from(self.number_of_hash_functions())
			* f64::ln(1.0f64 - (self.pop_count() as f64) / f_m);
		fest.ceil() as u64
	}

	fn optimal_k_num(bitmap_bits: u64, items_count: usize) -> u32 {
		let m = bitmap_bits as f64;
		let n = items_count as f64;
		let k_num = (m / n * f64::ln(2.0f64)).ceil() as u32;
		cmp::max(k_num, 1)
	}

	// SipHash is supposed to be a second preimage resistant hash function, but it is not
	// designed to be collision resistant.  If the adversary can control the items (in our
	// use case, memory locations accessed), then they should be able to generate
	// collisions here.  The use in a Bloom filter means that we will end up not setting
	// nearly as many bits as if random functions were used and the SwamidassBaldi estimate
	// will be off.  This means that if we were to implement a cost metric based on the
	// number of distinct memory locations accessed, we must fix this.  Another potential
	// effect of adversarially induced hash collisions is to create conflicts when a simple
	// source analysis would not indicate conflicts, but this would primarily be the
	// contract author creating barriers to parallelism for her/his own contract; the
	// author has no incentive to do so.
	fn sip_hash<T>(item: &T) -> u64
	where
		T: Hash,
	{
		let mut sip = SipHasher::new();
		item.hash(&mut sip);
		let hash = sip.finish();
		hash
	}

	// bloom_hash is supposed to yield independent hash functions of the data, so would be
	// better / more obviously correct to just add additional input to SipHash as a prefix
	// to the item.  However, even though SipHash is cheap compared with other
	// cryptographic hash functions, that might be too high.  Instead, we cheat slightly:
	// we know that the entropy in SipHash's output is not fully used when we mod by the
	// bitmap size, so we can re-use it -- after modular reduction by a (hopefully)
	// different modulus.
	fn bloom_hash(base_hash: u64, k_i: u32) -> u64 {
		base_hash.wrapping_add(u64::from(k_i).wrapping_mul(base_hash) % 0xffff_ffff_ffff_ffc5)
	}

	pub fn intersect(&self, other: &Self) -> Result<Self, Error> {
		if self.number_of_bits() != other.number_of_bits() {
			return Err(Error::BitmapSizeMismatch);
		}
		if self.number_of_hash_functions() != other.number_of_hash_functions() {
			return Err(Error::NumberOfHashFnMismatch);
		}
		match self.bitmap.intersect(&other.bitmap) {
			Err(e) => Err(e),
			Ok(wedge) => Ok(Self {
				bitmap: wedge,
				bitmap_bits: self.bitmap_bits,
				k_num: self.k_num,
			}),
		}
	}

	pub fn union(&self, other: &Self) -> Result<Self, Error> {
		if self.number_of_bits() != other.number_of_bits() {
			return Err(Error::BitmapSizeMismatch);
		}
		if self.number_of_hash_functions() != other.number_of_hash_functions() {
			return Err(Error::NumberOfHashFnMismatch);
		}
		match self.bitmap.union(&other.bitmap) {
			Err(e) => Err(e),
			Ok(vee) => Ok(Self {
				bitmap: vee,
				bitmap_bits: self.bitmap_bits,
				k_num: self.k_num,
			}),
		}
	}
}

#[test]
fn test_detection() {
	let mut bf = BloomFilter::new_for_fp_rate(10000, 0.001);
	assert!(!bf.check(&0));
	bf.set(&0);
	assert!(bf.check(&0));
	assert!(!bf.check(&1));
	bf.set(&1);
	assert!(bf.check(&0));
	assert!(bf.check(&1));
}

#[test]
fn test_saturation_1x() {
	let mut bf = BloomFilter::new_for_fp_rate(1000, 0.001);
	for i in 0..1000 {
		bf.set(&i);
	}
	assert!(bf.saturation() > 0.45);
}

#[test]
fn test_saturation_10x() {
	let mut bf = BloomFilter::new_for_fp_rate(1000, 0.001);
	for i in 0..10000 {
		bf.set(&i);
	}
	assert!(bf.saturation() > 0.98);
}

#[test]
fn test_estimate() {
	let num_elts = 1000;
	let mut bf = BloomFilter::new_for_fp_rate(num_elts, 0.001);
	for i in 0..num_elts {
		bf.set(&i);
	}
	let est_elts = bf.est_num_entries();
	let lower = (0.8 * (num_elts as f64)) as u64;
	let upper = (1.2 * (num_elts as f64)) as u64;
	assert!(est_elts > lower);
	assert!(est_elts < upper);
}

#[test]
fn test_self_intersect() {
	let num_elts = 1000;
	let mut bf1 = BloomFilter::new_for_fp_rate(num_elts, 0.001);
	for i in 0..num_elts {
		bf1.set(&i);
	}
	let bf3 = bf1.intersect(&bf1).unwrap();
	let lower = (0.8 * (num_elts as f64)) as u64;
	let upper = (1.2 * (num_elts as f64)) as u64;

	for i in 0..num_elts {
		assert!(bf3.check(&i));
	}

	let est = bf3.est_num_entries();
	assert!(est > lower);
	assert!(est < upper);
}

#[test]
fn test_intersect() {
	let num_elts = 1000;
	let omitted = 100;
	let mut bf1 = BloomFilter::new_for_fp_rate(num_elts, 0.001);
	let mut bf2 = BloomFilter::new_for_fp_rate(num_elts, 0.001);
	for i in 0..num_elts {
		bf1.set(&i);
	}
	for i in omitted..(num_elts + omitted) {
		bf2.set(&i);
	}
	let bf3 = bf1.intersect(&bf2).unwrap();
	let actual_overlap = num_elts - omitted;
	let lower = (0.8 * (actual_overlap as f64)) as u64;
	let upper = (1.2 * (actual_overlap as f64)) as u64;

	for i in omitted..num_elts {
		assert!(bf3.check(&i));
	}

	let est = bf3.est_num_entries();
	assert!(est > lower);
	assert!(est < upper);
}

#[test]
fn test_self_union() {
	let num_elts = 1000;
	let mut bf1 = BloomFilter::new_for_fp_rate(num_elts, 0.001);
	for i in 0..100 {
		bf1.set(&i);
	}
	let bf3 = bf1.union(&bf1).unwrap();

	for i in 0..100 {
		assert!(bf3.check(&i));
	}

	let actual_count = (100 - 0);
	let lower = (0.8 * (actual_count as f64)) as u64;
	let upper = (1.2 * (actual_count as f64)) as u64;

	let est = bf3.est_num_entries();
	assert!(est > lower);
	assert!(est < upper);
}

#[test]
fn test_union() {
	let num_elts = 1000;
	let mut bf1 = BloomFilter::new_for_fp_rate(num_elts, 0.001);
	let mut bf2 = BloomFilter::new_for_fp_rate(num_elts, 0.001);
	for i in 0..100 {
		bf1.set(&i);
	}
	for i in 200..250 {
		bf2.set(&i);
	}
	let bf3 = bf1.union(&bf2).unwrap();

	for i in 0..100 {
		assert!(bf3.check(&i));
	}
	for i in 200..250 {
		assert!(bf3.check(&i));
	}

	let actual_count = (100 - 0) + (250 - 200);
	let lower = (0.8 * (actual_count as f64)) as u64;
	let upper = (1.2 * (actual_count as f64)) as u64;

	let est = bf3.est_num_entries();
	assert!(est > lower);
	assert!(est < upper);
}

#[test]
fn test_false_positive() {
	let num_elts = 1000;
	let req_fp_rate = 0.001;

	let start = 2000;
	let count = 10000;

	let mut bf = BloomFilter::new_for_fp_rate(num_elts + count, req_fp_rate);
	for i in 0..num_elts {
		bf.set(&i);
	}

	let mut num_fp = 0;

	for i in start..(start + count) {
		if bf.check(&i) {
			num_fp = num_fp + 1
		}
	}

	let fp_rate = num_fp as f64 / count as f64;

	println!("{}", fp_rate);
	assert!(fp_rate < 1.1 * req_fp_rate);
}
