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

use bytes::Bytes;
use ethereum_types::{H256, U256};
use ethjson;
use hash::keccak;
use hashdb::HashDB;
use itertools::Itertools;
use rlp::{self, RlpStream};
use state::Account;
use std::collections::BTreeMap;
use std::fmt;
use trie::TrieFactory;
use triehash::sec_trie_root;
use types::account_diff::*;

use crate::mkvs::MKVS;

#[derive(Debug, Clone, PartialEq, Eq)]
/// An account, expressed as Plain-Old-Data (hence the name).
/// Does not have a DB overlay cache, code hash or anything like that.
pub struct PodAccount {
	/// The balance of the account.
	pub balance: U256,
	/// The nonce of the account.
	pub nonce: U256,
	/// The code of the account or `None` in the special case that it is unknown.
	pub code: Option<Bytes>,
	/// The storage of the account.
	pub storage: BTreeMap<H256, Vec<u8>>,
	/// Storage expiry (Unix timestamp).
	pub storage_expiry: u64,
}

impl PodAccount {
	/// Convert Account to a PodAccount.
	/// NOTE: This will silently fail unless the account is fully cached.
	pub fn from_account(acc: &Account) -> PodAccount {
		PodAccount {
			balance: *acc.balance(),
			nonce: *acc.nonce(),
			storage: acc
				.storage_changes()
				.iter()
				.fold(BTreeMap::new(), |mut m, (k, v)| {
					m.insert(k.clone(), v.clone());
					m
				}),
			code: acc.code().map(|x| x.to_vec()),
			storage_expiry: acc.storage_expiry(),
		}
	}

	/// Returns the RLP for this account.
	pub fn rlp(&self) -> Bytes {
		let mut stream = RlpStream::new_list(5);
		stream.append(&self.nonce);
		stream.append(&self.balance);
		stream.append(&sec_trie_root(
			self.storage
				.iter()
				.map(|(k, v)| (k, rlp::encode(&U256::from(&**v)))),
		));
		stream.append(&keccak(&self.code.as_ref().unwrap_or(&vec![])));
		stream.append(&self.storage_expiry);
		stream.out()
	}

	pub fn insert_additional(&self, mkvs: &mut MKVS) {
		match self.code {
			Some(ref c) if !c.is_empty() => {
				mkvs.insert(MKVS_KEY_CODE, c);
			}
			_ => {}
		}
		for (k, v) in &self.storage {
			let mut key = MKVS_KEY_PREFIX_STORAGE.to_vec();
			key.extend_from_slice(k);
			mkvs.insert(&key, &rlp::encode(v));
		}
	}
}

// It is assumed ethjson::blockchain::Account has storage values as H256.
impl From<ethjson::blockchain::Account> for PodAccount {
	fn from(a: ethjson::blockchain::Account) -> Self {
		PodAccount {
			balance: a.balance.into(),
			nonce: a.nonce.into(),
			code: Some(a.code.into()),
			storage: a
				.storage
				.into_iter()
				.map(|(key, value)| {
					let key: U256 = key.into();
					let value: U256 = value.into();
					(H256::from(key), H256::from(value).to_vec())
				})
				.collect(),
			storage_expiry: a.storage_expiry,
		}
	}
}

// It is assumed ethjson::spec::Account has storage values as H256.
impl From<ethjson::spec::Account> for PodAccount {
	fn from(a: ethjson::spec::Account) -> Self {
		PodAccount {
			balance: a.balance.map_or_else(U256::zero, Into::into),
			nonce: a.nonce.map_or_else(U256::zero, Into::into),
			code: Some(a.code.map_or_else(Vec::new, Into::into)),
			storage: a.storage.map_or_else(BTreeMap::new, |s| {
				s.into_iter()
					.map(|(key, value)| {
						let key: U256 = key.into();
						let value: U256 = value.into();
						(H256::from(key), H256::from(value).to_vec())
					})
					.collect()
			}),
			storage_expiry: a.storage_expiry.unwrap_or(0),
		}
	}
}

impl fmt::Display for PodAccount {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(
			f,
			"(bal={}; nonce={}; code={} bytes, #{}; storage={} items; expiry={})",
			self.balance,
			self.nonce,
			self.code.as_ref().map_or(0, |c| c.len()),
			self.code.as_ref().map_or_else(H256::new, |c| keccak(c)),
			self.storage.len(),
			self.storage_expiry,
		)
	}
}

/// Determine difference between two optionally existant `Account`s. Returns None
/// if they are the same.
pub fn diff_pod(pre: Option<&PodAccount>, post: Option<&PodAccount>) -> Option<AccountDiff> {
	match (pre, post) {
		(None, Some(x)) => Some(AccountDiff {
			balance: Diff::Born(x.balance),
			nonce: Diff::Born(x.nonce),
			code: Diff::Born(x.code.as_ref().expect("account is newly created; newly created accounts must be given code; all caches should remain in place; qed").clone()),
			storage: x.storage.iter().map(|(k, v)| (k.clone(), Diff::Born(v.clone()))).collect(),
			storage_expiry: Diff::Born(x.storage_expiry),
		}),
		(Some(x), None) => Some(AccountDiff {
			balance: Diff::Died(x.balance),
			nonce: Diff::Died(x.nonce),
			code: Diff::Died(x.code.as_ref().expect("account is deleted; only way to delete account is running SUICIDE; account must have had own code cached to make operation; all caches should remain in place; qed").clone()),
			storage: x.storage.iter().map(|(k, v)| (k.clone(), Diff::Died(v.clone()))).collect(),
			storage_expiry: Diff::Died(x.storage_expiry),
		}),
		(Some(pre), Some(post)) => {
			let storage: Vec<_> = pre.storage.keys().merge(post.storage.keys())
				.filter(|k| pre.storage.get(k).unwrap_or(&H256::new().to_vec()) != post.storage.get(k).unwrap_or(&H256::new().to_vec()))
				.collect();
			let r = AccountDiff {
				balance: Diff::new(pre.balance, post.balance),
				nonce: Diff::new(pre.nonce, post.nonce),
				code: match (pre.code.clone(), post.code.clone()) {
					(Some(pre_code), Some(post_code)) => Diff::new(pre_code, post_code),
					_ => Diff::Same,
				},
				storage: storage.into_iter().map(|k|
					(k.clone(), Diff::new(
						pre.storage.get(k).cloned().unwrap_or_else(|| H256::new().to_vec()),
						post.storage.get(k).cloned().unwrap_or_else(|| H256::new().to_vec())
					))).collect(),
				storage_expiry: Diff::new(pre.storage_expiry, post.storage_expiry),
			};
			if r.balance.is_same() && r.nonce.is_same() && r.code.is_same() && r.storage.is_empty() && r.storage_expiry.is_same() {
				None
			} else {
				Some(r)
			}
		},
		_ => None,
	}
}

#[cfg(test)]
mod test {
	use super::{diff_pod, PodAccount};
	use ethereum_types::H256;
	use std::collections::BTreeMap;
	use types::account_diff::*;

	#[test]
	fn existence() {
		let a = PodAccount {
			balance: 69.into(),
			nonce: 0.into(),
			code: Some(vec![]),
			storage: map![],
			storage_expiry: 0,
		};
		assert_eq!(diff_pod(Some(&a), Some(&a)), None);
		assert_eq!(
			diff_pod(None, Some(&a)),
			Some(AccountDiff {
				balance: Diff::Born(69.into()),
				nonce: Diff::Born(0.into()),
				code: Diff::Born(vec![]),
				storage: map![],
				storage_expiry: Diff::Born(0),
			})
		);
	}

	#[test]
	fn basic() {
		let a = PodAccount {
			balance: 69.into(),
			nonce: 0.into(),
			code: Some(vec![]),
			storage: map![],
			storage_expiry: 0,
		};
		let b = PodAccount {
			balance: 42.into(),
			nonce: 1.into(),
			code: Some(vec![]),
			storage: map![],
			storage_expiry: 1000,
		};
		assert_eq!(
			diff_pod(Some(&a), Some(&b)),
			Some(AccountDiff {
				balance: Diff::Changed(69.into(), 42.into()),
				nonce: Diff::Changed(0.into(), 1.into()),
				code: Diff::Same,
				storage: map![],
				storage_expiry: Diff::Changed(0, 1000),
			})
		);
	}

	#[test]
	fn code() {
		let a = PodAccount {
			balance: 0.into(),
			nonce: 0.into(),
			code: Some(vec![]),
			storage: map![],
			storage_expiry: 0,
		};
		let b = PodAccount {
			balance: 0.into(),
			nonce: 1.into(),
			code: Some(vec![0]),
			storage: map![],
			storage_expiry: 0,
		};
		assert_eq!(
			diff_pod(Some(&a), Some(&b)),
			Some(AccountDiff {
				balance: Diff::Same,
				nonce: Diff::Changed(0.into(), 1.into()),
				code: Diff::Changed(vec![], vec![0]),
				storage: map![],
				storage_expiry: Diff::Same,
			})
		);
	}

	#[test]
	fn storage() {
		let a = PodAccount {
			balance: 0.into(),
			nonce: 0.into(),
			code: Some(vec![]),
			storage: map_into![1 => H256::from(1).to_vec(), 2 => H256::from(2).to_vec(), 3 => H256::from(3).to_vec(), 4 => H256::from(4).to_vec(), 5 => H256::from(0).to_vec(), 6 => H256::from(0).to_vec(), 7 => H256::from(0).to_vec()],
			storage_expiry: 0,
		};
		let b = PodAccount {
			balance: 0.into(),
			nonce: 0.into(),
			code: Some(vec![]),
			storage: map_into![1 => H256::from(1).to_vec(), 2 => H256::from(3).to_vec(), 3 => H256::from(0).to_vec(), 5 => H256::from(0).to_vec(), 7 => H256::from(7).to_vec(), 8 => H256::from(0).to_vec(), 9 => H256::from(9).to_vec()],
			storage_expiry: 0,
		};
		assert_eq!(
			diff_pod(Some(&a), Some(&b)),
			Some(AccountDiff {
				balance: Diff::Same,
				nonce: Diff::Same,
				code: Diff::Same,
				storage: map![
					2.into() => Diff::new(H256::from(2).to_vec(), H256::from(3).to_vec()),
					3.into() => Diff::new(H256::from(3).to_vec(), H256::from(0).to_vec()),
					4.into() => Diff::new(H256::from(4).to_vec(), H256::from(0).to_vec()),
					7.into() => Diff::new(H256::from(0).to_vec(), H256::from(7).to_vec()),
					9.into() => Diff::new(H256::from(0).to_vec(), H256::from(9).to_vec())
				],
				storage_expiry: Diff::Same,
			})
		);
	}
}
