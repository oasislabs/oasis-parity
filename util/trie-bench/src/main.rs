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
extern crate hashdb;
extern crate ethereum_types;
#[macro_use]
extern crate serde_derive;
extern crate docopt;
extern crate rand;
extern crate ethcore_logger as log;
extern crate keccak_hash as keccak;

//#[macro_use]
extern crate log as rlog;

use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::collections::HashMap;
use docopt::Docopt;
use ethereum_types::{H256};
use patricia_trie::{TrieDBMut as EthereumTrie, TrieMut};
use patricia_trie::{CompactTrieDBMut as CompactTrie};
use kvdb::{DBValue, DBTransaction};
use keccak::{keccak, KECCAK_NULL_RLP};
use rand::Rng;

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
	flag_dir: Option<String>,
	flag_log: String,
}

struct Db {
	db: kvdb_rocksdb::Database,
	reads: AtomicUsize,
	writes: u64,
	deletions: u64,
	transaction: DBTransaction,
}

impl Db {
	fn commit(&mut self) {
		let tx = ::std::mem::replace(&mut self.transaction, DBTransaction::new());
		self.db.write(tx).expect("Error writing to the database");
	}
}

impl hashdb::HashDB for Db {
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

fn open_db(args: &Args) -> Db {
	let mut path = PathBuf::from(args.flag_dir.as_ref().map(|s| s.as_str()).unwrap_or(&"trie-bench-db"));
	path.push(if args.flag_ethereum { "ethereum" } else { "compact" });
	std::fs::create_dir_all(&path).expect("Error creating db dir");
	let db = kvdb_rocksdb::Database::open_default(&path.to_string_lossy()).expect("Error opening the database");
	Db {
		db,
		reads: AtomicUsize::new(0),
		writes: 0,
		deletions: 0,
		transaction: DBTransaction::new(),
	}
}

fn generate(args: Args) {
	let mut db = open_db(&args);

	let mut root = H256::new();

	let mut rng = rand::Isaac64Rng::new_unseeded();
	let mut key = H256::new();
	let mut total: u64 = 0;
	let compact = !args.flag_ethereum;
	println!("Using {} trie", if compact { "compact" } else { "ethereum" });

	{
		let mut gen_batch = |trie: &mut TrieMut| {
			for _ in 0 .. 10000 {
				rng.fill_bytes(&mut key);
				let mut value: [u8; 64] = [0u8; 64];
				&mut value[..32].copy_from_slice(&key);
				&mut value[32..].copy_from_slice(&key);
				trie.insert(&key, &value).expect("Error inserting into the trie");
				total = total + 1;
			}
		};

		for batch in 0 .. 1000 {
			match (batch == 0, compact) {
				(true, false) => gen_batch(&mut EthereumTrie::new(&mut db, &mut root)),
				(false, false) => gen_batch(&mut EthereumTrie::from_existing(&mut db, &mut root).expect("Error creating trie")),
				(true, true) => gen_batch(&mut CompactTrie::new(&mut db, &mut root)),
				(false, true) => gen_batch(&mut CompactTrie::from_existing(&mut db, &mut root).expect("Error creating trie")),
			}
			db.commit();
			if batch % 1 == 0 {
				println!("Batch {}", batch);
			}
		}
	}
	println!("Done. {} keys, {} nodes inserted, {} deleted, {} queried", total, db.writes, db.deletions, db.reads.get_mut());
}

fn query(args: Args) {
	let mut _db = open_db(&args);
}


