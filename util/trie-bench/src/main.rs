// Copyright 2015-2017 Parity Technologies (UK) Ltd.
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

//! Parity EVM interpreter binary.

#![warn(missing_docs)]

extern crate patricia_trie;
extern crate kvdb;
extern crate kvdb_rocksdb;
extern crate lmdb_zero as lmdb;
extern crate hashdb;
extern crate ethereum_types;
#[macro_use]
extern crate serde_derive;
extern crate docopt;
extern crate rand;
extern crate ethcore_logger as log;
extern crate keccak_hash as keccak;
extern crate parking_lot;

//#[macro_use]
extern crate log as rlog;

use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::collections::HashMap;
use docopt::Docopt;
use ethereum_types::{H256};
use patricia_trie::{TrieDBMut as EthereumTrie, TrieMut};
use patricia_trie::{CompactTrieDBMut as CompactTrie, Base2TrieDBMut as Base2Trie};
use kvdb::{DBValue, DBTransaction};
use keccak::{keccak, KECCAK_NULL_RLP};
use rand::Rng;
use lmdb::LmdbResultExt;

const NULL_RLP: [u8; 1] = [0x80; 1];

const USAGE: &'static str = r#"
EVM implementation for Parity.
  Copyright 2018 Parity Technologies (UK) Ltd

Usage:
    trie-bench generate [options]
    trie-bench query [options]
    parity-evm [-h | --help]

Trie options:
    --ethereum         Use standard ethereum trie.
    --compact          Use compact trie.
    --base2            Use base2 trie.
    --lmdb             Use LMDB backend.

General options:
    -d, --dir          Set data dir.
	-l, --log LEVEL    Specify the logging level. Must conform to the same format as RUST_LOG [default: warn].
	-h, --help         Display this message and exit.
"#;

#[derive(Debug, Deserialize)]
struct Args {
	cmd_generate: bool,
	cmd_query: bool,
	flag_ethereum: bool,
	flag_compact: bool,
	flag_base2: bool,
	flag_lmdb: bool,
	flag_dir: Option<String>,
	flag_log: String,
}

trait DB {
	fn commit(&mut self);
	fn print_stats(&mut self);
	fn as_hashdb(&mut self) -> &mut hashdb::HashDB;
}

struct RocksDb {
	db: kvdb_rocksdb::Database,
	reads: AtomicUsize,
	writes: u64,
	deletions: u64,
	transaction: DBTransaction,
}


impl DB for RocksDb {
	fn commit(&mut self) {
		let tx = ::std::mem::replace(&mut self.transaction, DBTransaction::new());
		self.db.write(tx).expect("Error writing to the database");
	}

	fn print_stats(&mut self) {
		println!("{} inserted, {} deleted, {} queried", self.writes, self.deletions, self.reads.get_mut());
	}

	fn as_hashdb(&mut self) -> &mut hashdb::HashDB {
		self
	}
}

impl hashdb::HashDB for RocksDb {
	fn get(&self, key: &H256) -> Option<DBValue> {

		if key == &KECCAK_NULL_RLP {
			return Some(DBValue::from_slice(&NULL_RLP));
		}

		self.reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
		self.db.get(None, key).expect("Error reading DB")
	}

	fn keys(&self) -> HashMap<H256, i32> {
		self.db.iter(None).expect("Error reading DB").map(|(k, _)| (H256::from_slice(&k), 1)).collect()
	}

	fn contains(&self, key: &H256) -> bool {
		self.get(key).is_some()
	}

	fn insert(&mut self, value: &[u8]) -> H256 {
		if value == &NULL_RLP {
			return KECCAK_NULL_RLP.clone();
		}
		self.writes = self.writes + 1;
		let key = keccak(value);
		self.transaction.put(None, &key, &value);
		key
	}

	fn emplace(&mut self, key: H256, value: DBValue) {
		if &*value == &NULL_RLP {
			return;
		}
		self.writes = self.writes + 1;
		self.transaction.put(None, &key, &value);
	}

	fn remove(&mut self, key: &H256) {
		if key == &KECCAK_NULL_RLP {
			return;
		}

		self.deletions = self.deletions + 1;
		self.transaction.delete(None, &key);
	}
}

unsafe impl Send for Lmdb {}
unsafe impl Sync for Lmdb {}

struct Lmdb {
	env: Arc<lmdb::Environment>,
	db: lmdb::Database<'static>,
	transaction: Option<lmdb::WriteTransaction<'static>>,
	read: Option<lmdb::ReadTransaction<'static>>,
	reads: AtomicUsize,
	writes: u64,
	deletions: u64,
}

impl DB for Lmdb {
	fn commit(&mut self) {
		self.transaction.take().unwrap().commit().unwrap();
		self.transaction = Some(lmdb::WriteTransaction::new(self.env.clone()).unwrap());
		let t = self.read.take().unwrap().reset();
		self.read = Some(t.renew().unwrap());
	}

	fn print_stats(&mut self) {
		println!("{} inserted, {} deleted, {} queried", self.writes, self.deletions, self.reads.get_mut());
	}

	fn as_hashdb(&mut self) -> &mut hashdb::HashDB {
		self
	}
}

impl hashdb::HashDB for Lmdb {
	fn get(&self, key: &H256) -> Option<DBValue> {

		if key == &KECCAK_NULL_RLP {
			return Some(DBValue::from_slice(&NULL_RLP));
		}

		self.reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
		let access = self.read.as_ref().unwrap().access();
		let val: Option<&[u8]> = access.get(&self.db, &key[..]).to_opt().unwrap();
		val.map(|v| DBValue::from_slice(v))
	}

	fn keys(&self) -> HashMap<H256, i32> {
		unimplemented!()
	}

	fn contains(&self, key: &H256) -> bool {
		let access = self.read.as_ref().unwrap().access();
		let val: Option<&[u8]> = access.get(&self.db, &key[..]).to_opt().unwrap();
		val.is_some()
	}

	fn insert(&mut self, value: &[u8]) -> H256 {
		if value == &NULL_RLP {
			return KECCAK_NULL_RLP.clone();
		}
		self.writes = self.writes + 1;
		let key = keccak(value);
		self.transaction.as_ref().unwrap().access().put(&self.db, &key[..], value, lmdb::put::Flags::empty()).unwrap();
		key
	}

	fn emplace(&mut self, key: H256, value: DBValue) {
		if &*value == &NULL_RLP {
			return;
		}
		self.writes = self.writes + 1;
		self.transaction.as_ref().unwrap().access().put(&self.db, &key[..], &value[..], lmdb::put::Flags::empty()).unwrap();
	}

	fn remove(&mut self, key: &H256) {
		if key == &KECCAK_NULL_RLP {
			return;
		}

		self.deletions = self.deletions + 1;
		self.transaction.as_ref().unwrap().access().del_key(&self.db, &key[..]).unwrap();
	}
}

fn main() {
	let args: Args = Docopt::new(USAGE).and_then(|d| d.deserialize()).unwrap_or_else(|e| e.exit());
	initialize_logger(&args.flag_log).expect("Error parsing log filter");

	if args.cmd_query {
		query(args)
	} else if args.cmd_generate {
		generate(args)
	}
}

fn initialize_logger(log_level: &str) -> Result<(), String> {
	let mut l = log::Config::default();
	l.mode = Some(log_level.to_owned());
	log::setup_log(&l)?;
	Ok(())
}

fn open_db(args: &Args) -> Box<DB> {
	let mut path = PathBuf::from(args.flag_dir.as_ref().map(|s| s.as_str()).unwrap_or(&"trie-bench-db"));
	path.push(if args.flag_compact { "compact" } else { if args.flag_base2 { "base2" } else { "ethereum" } });
	path.push(if args.flag_lmdb { "lmdb" } else { "rocksdb" });
	std::fs::create_dir_all(&path).expect("Error creating db dir");
	if args.flag_lmdb {
		let env = Arc::new(unsafe {
			let mut e = lmdb::EnvBuilder::new().unwrap().open(&path.to_string_lossy(), lmdb::open::NOSYNC, 0o600).unwrap();
			e.set_mapsize(1024 * 1024 * 1024 * 1024).unwrap(); //1 TB
			e
		});
		let db = lmdb::Database::open(env.clone(), None, &lmdb::DatabaseOptions::defaults()).unwrap();
		let transaction = lmdb::WriteTransaction::new(env.clone()).unwrap();
		let read_tx = lmdb::ReadTransaction::new(env.clone()).unwrap();
		Box::new(Lmdb {
			env,
			db,
			transaction: Some(transaction),
			read: Some(read_tx),
			reads: AtomicUsize::new(0),
			writes: 0,
			deletions: 0,
		})
	} else {
		let db = kvdb_rocksdb::Database::open_default(&path.to_string_lossy()).expect("Error opening the database");
		Box::new(RocksDb {
			db,
			reads: AtomicUsize::new(0),
			writes: 0,
			deletions: 0,
			transaction: DBTransaction::new(),
		})
	}
}

fn generate(args: Args) {
	let mut db = open_db(&args);

	let mut root = H256::new();

	let mut rng = rand::Isaac64Rng::new_unseeded();
	let mut key = H256::new();
	let compact = args.flag_compact;
	let base2 = args.flag_base2;
	println!("Using {} trie", if compact { "compact" } else { if base2 { "base2"} else { "ethereum" } });

	{
		let mut gen_batch = |trie: &mut TrieMut| {
			for _ in 0 .. 10000 {
				rng.fill_bytes(&mut key);
				let mut value: [u8; 64] = [0u8; 64];
				&mut value[..32].copy_from_slice(&key);
				&mut value[32..].copy_from_slice(&key);
				trie.insert(&key, &value).expect("Error inserting into the trie");
			}
		};

		for batch in 0 .. 100 {
			match (batch == 0, compact, base2) {
				(true, false, false) => gen_batch(&mut EthereumTrie::new(db.as_hashdb(), &mut root)),
				(false, false, false) => gen_batch(&mut EthereumTrie::from_existing(db.as_hashdb(), &mut root).expect("Error creating trie")),
				(true, true, _) => gen_batch(&mut CompactTrie::new(db.as_hashdb(), &mut root)),
				(false, true, _) => gen_batch(&mut CompactTrie::from_existing(db.as_hashdb(), &mut root).expect("Error creating trie")),
				(true, _, true) => gen_batch(&mut Base2Trie::new(db.as_hashdb(), &mut root)),
				(false, _, true) => gen_batch(&mut Base2Trie::from_existing(db.as_hashdb(), &mut root).expect("Error creating trie")),
			}
			db.commit();
			if batch % 1 == 0 {
				println!("Batch {}", batch);
			}
		}
	}
	db.print_stats();
}

fn query(args: Args) {
	let mut _db = open_db(&args);
}


