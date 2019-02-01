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

use std::str::FromStr;
use std::sync::Arc;
use hash::keccak;
use io::IoChannel;
use client::{BlockChainClient, Client, ClientConfig, BlockId, ChainInfo, BlockInfo, PrepareOpenBlock, ImportSealedBlock, ImportBlock};
use state::{self, State, CleanupMode};
use executive::{Executive, TransactOptions};
use ethereum;
use block::IsBlock;
use test_helpers::{
	generate_dummy_client, push_blocks_to_client, get_test_client_with_blocks, get_good_dummy_block_seq,
	generate_dummy_client_with_data, get_good_dummy_block, get_bad_state_dummy_block
};
use types::filter::Filter;
use ethereum_types::{U256, Address};
use kvdb_rocksdb::{Database, DatabaseConfig};
use miner::Miner;
use spec::Spec;
use views::BlockView;
use ethkey::KeyPair;
use transaction::{PendingTransaction, Transaction, Action, Condition};
use miner::MinerService;
use rlp::{RlpStream, EMPTY_LIST_RLP};
use tempdir::TempDir;

#[test]
fn imports_from_empty() {
	let tempdir = TempDir::new("").unwrap();
	let spec = Spec::new_test();
	let db_config = DatabaseConfig::with_columns(::db::NUM_COLUMNS);
	let client_db = Arc::new(Database::open(&db_config, tempdir.path().to_str().unwrap()).unwrap());

	let client = Client::new(
		ClientConfig::default(),
		&spec,
		client_db,
		Arc::new(Miner::new_for_tests(&spec, None)),
		IoChannel::disconnected(),
	).unwrap();
	client.import_verified_blocks();
	client.flush_queue();
}

#[test]
fn should_return_registrar() {
	let tempdir = TempDir::new("").unwrap();
	let spec = ethereum::new_morden(&tempdir.path().to_owned());
	let db_config = DatabaseConfig::with_columns(::db::NUM_COLUMNS);
	let client_db = Arc::new(Database::open(&db_config, tempdir.path().to_str().unwrap()).unwrap());

	let client = Client::new(
		ClientConfig::default(),
		&spec,
		client_db,
		Arc::new(Miner::new_for_tests(&spec, None)),
		IoChannel::disconnected(),
	).unwrap();
	let params = client.additional_params();
	let address = &params["registrar"];

	assert_eq!(address.len(), 40);
	assert!(U256::from_str(address).is_ok());
}

#[test]
fn returns_state_root_basic() {
	let client = generate_dummy_client(6);
	let test_spec = Spec::new_test();
	let genesis_header = test_spec.genesis_header();

	assert!(client.state_data(genesis_header.state_root()).is_some());
}

#[test]
fn imports_good_block() {
	let tempdir = TempDir::new("").unwrap();
	let spec = Spec::new_test();
	let db_config = DatabaseConfig::with_columns(::db::NUM_COLUMNS);
	let client_db = Arc::new(Database::open(&db_config, tempdir.path().to_str().unwrap()).unwrap());

	let client = Client::new(
		ClientConfig::default(),
		&spec,
		client_db,
		Arc::new(Miner::new_for_tests(&spec, None)),
		IoChannel::disconnected(),
	).unwrap();
	let good_block = get_good_dummy_block();
	if client.import_block(good_block).is_err() {
		panic!("error importing block being good by definition");
	}
	client.flush_queue();
	client.import_verified_blocks();

	let block = client.block_header(BlockId::Number(1)).unwrap();
	assert!(!block.into_inner().is_empty());
}

#[test]
fn fails_to_import_block_with_invalid_rlp() {
	use error::{BlockImportError, BlockImportErrorKind};

	let client = generate_dummy_client(6);
	let mut rlp = RlpStream::new_list(3);
	rlp.append_raw(&EMPTY_LIST_RLP, 1); // empty header
	rlp.append_raw(&EMPTY_LIST_RLP, 1);
	rlp.append_raw(&EMPTY_LIST_RLP, 1);
	let invalid_header_block = rlp.out();

	match client.import_block(invalid_header_block) {
		Err(BlockImportError(BlockImportErrorKind::Decoder(_), _)) => (), // all good
		Err(_) => panic!("Should fail with a decoder error"),
		Ok(_) => panic!("Should not import block with invalid header"),
	}
}

#[test]
fn query_none_block() {
	let tempdir = TempDir::new("").unwrap();
	let spec = Spec::new_test();
	let db_config = DatabaseConfig::with_columns(::db::NUM_COLUMNS);
	let client_db = Arc::new(Database::open(&db_config, tempdir.path().to_str().unwrap()).unwrap());

	let client = Client::new(
		ClientConfig::default(),
		&spec,
		client_db,
		Arc::new(Miner::new_for_tests(&spec, None)),
		IoChannel::disconnected(),
	).unwrap();
    let non_existant = client.block_header(BlockId::Number(188));
	assert!(non_existant.is_none());
}

#[test]
fn query_bad_block() {
	let client = get_test_client_with_blocks(vec![get_bad_state_dummy_block()]);
	let bad_block: Option<_> = client.block_header(BlockId::Number(1));

	assert!(bad_block.is_none());
}

#[test]
fn returns_chain_info() {
	let dummy_block = get_good_dummy_block();
	let client = get_test_client_with_blocks(vec![dummy_block.clone()]);
	let block = view!(BlockView, &dummy_block);
	let info = client.chain_info();
	assert_eq!(info.best_block_hash, block.header().hash());
}

#[test]
fn returns_logs() {
	let dummy_block = get_good_dummy_block();
	let client = get_test_client_with_blocks(vec![dummy_block.clone()]);
	let logs = client.logs(Filter {
		from_block: BlockId::Earliest,
		to_block: BlockId::Latest,
		address: None,
		topics: vec![],
		limit: None,
	});
	assert_eq!(logs.len(), 0);
}

#[test]
fn returns_logs_with_limit() {
	let dummy_block = get_good_dummy_block();
	let client = get_test_client_with_blocks(vec![dummy_block.clone()]);
	let logs = client.logs(Filter {
		from_block: BlockId::Earliest,
		to_block: BlockId::Latest,
		address: None,
		topics: vec![],
		limit: None,
	});
	assert_eq!(logs.len(), 0);
}

#[test]
fn returns_block_body() {
	let dummy_block = get_good_dummy_block();
	let client = get_test_client_with_blocks(vec![dummy_block.clone()]);
	let block = view!(BlockView, &dummy_block);
	let body = client.block_body(BlockId::Hash(block.header().hash())).unwrap();
	let body = body.rlp();
	assert_eq!(body.item_count().unwrap(), 2);
	assert_eq!(body.at(0).unwrap().as_raw()[..], block.rlp().at(1).as_raw()[..]);
	assert_eq!(body.at(1).unwrap().as_raw()[..], block.rlp().at(2).as_raw()[..]);
}

#[test]
fn imports_block_sequence() {
	let client = generate_dummy_client(6);
	let block = client.block_header(BlockId::Number(5)).unwrap();

	assert!(!block.into_inner().is_empty());
}

#[test]
fn can_collect_garbage() {
	let client = generate_dummy_client(100);
	client.tick(true);
	assert!(client.blockchain_cache_info().blocks < 100 * 1024);
}

#[test]
fn can_generate_gas_price_median() {
	let client = generate_dummy_client_with_data(3, 1, slice_into![1, 2, 3]);
	assert_eq!(Some(&U256::from(2)), client.gas_price_corpus(3).median());

	let client = generate_dummy_client_with_data(4, 1, slice_into![1, 4, 3, 2]);
	assert_eq!(Some(&U256::from(3)), client.gas_price_corpus(3).median());
}

#[test]
fn can_generate_gas_price_histogram() {
	let client = generate_dummy_client_with_data(20, 1, slice_into![6354,8593,6065,4842,7845,7002,689,4958,4250,6098,5804,4320,643,8895,2296,8589,7145,2000,2512,1408]);

	let hist = client.gas_price_corpus(20).histogram(5).unwrap();
	let correct_hist = ::stats::Histogram { bucket_bounds: vec_into![643, 2294, 3945, 5596, 7247, 8898], counts: vec![4,2,4,6,4] };
	assert_eq!(hist, correct_hist);
}

#[test]
fn empty_gas_price_histogram() {
	let client = generate_dummy_client_with_data(20, 0, slice_into![]);

	assert!(client.gas_price_corpus(20).histogram(5).is_none());
}

#[test]
fn corpus_is_sorted() {
	let client = generate_dummy_client_with_data(2, 1, slice_into![U256::from_str("11426908979").unwrap(), U256::from_str("50426908979").unwrap()]);
	let corpus = client.gas_price_corpus(20);
	assert!(corpus[0] < corpus[1]);
}

#[test]
fn can_handle_long_fork() {
	let client = generate_dummy_client(1200);
	for _ in 0..20 {
		client.import_verified_blocks();
	}
	assert_eq!(1200, client.chain_info().best_block_number);

	push_blocks_to_client(&client, 45, 1201, 800);
	push_blocks_to_client(&client, 49, 1201, 800);
	push_blocks_to_client(&client, 53, 1201, 600);

	for _ in 0..400 {
		client.import_verified_blocks();
	}
	assert_eq!(2000, client.chain_info().best_block_number);
}

#[test]
fn can_mine() {
	let dummy_blocks = get_good_dummy_block_seq(2);
	let client = get_test_client_with_blocks(vec![dummy_blocks[0].clone()]);

	let b = client.prepare_open_block(Address::default(), (3141562.into(), 31415620.into()), vec![]).close();

	assert_eq!(*b.block().header().parent_hash(), view!(BlockView, &dummy_blocks[0]).header_view().hash());
}

#[test]
fn change_history_size() {
	let tempdir = TempDir::new("").unwrap();
	let test_spec = Spec::new_null();
	let mut config = ClientConfig::default();
	let db_config = DatabaseConfig::with_columns(::db::NUM_COLUMNS);
	let client_db = Arc::new(Database::open(&db_config, tempdir.path().to_str().unwrap()).unwrap());

	config.history = 2;
	let address = Address::random();
	{
		let client = Client::new(
			ClientConfig::default(),
			&test_spec,
			client_db.clone(),
			Arc::new(Miner::new_for_tests(&test_spec, None)),
			IoChannel::disconnected()
		).unwrap();

		for _ in 0..20 {
			let mut b = client.prepare_open_block(Address::default(), (3141562.into(), 31415620.into()), vec![]);
			b.block_mut().state_mut().add_balance(&address, &5.into(), CleanupMode::NoEmpty).unwrap();
			b.block_mut().state_mut().commit().unwrap();
			let b = b.close_and_lock().seal(&*test_spec.engine, vec![]).unwrap();
			client.import_sealed_block(b).unwrap(); // account change is in the journal overlay
		}
	}
	let mut config = ClientConfig::default();
	config.history = 10;
	let client = Client::new(
		config,
		&test_spec,
		client_db,
		Arc::new(Miner::new_for_tests(&test_spec, None)),
		IoChannel::disconnected(),
	).unwrap();
	assert_eq!(client.state().balance(&address).unwrap(), 100.into());
}

#[test]
fn does_not_propagate_delayed_transactions() {
	let key = KeyPair::from_secret(keccak("test").into()).unwrap();
	let secret = key.secret();
	let tx0 = PendingTransaction::new(Transaction {
		nonce: 0.into(),
		gas_price: 0.into(),
		gas: 21000.into(),
		action: Action::Call(Address::default()),
		value: 0.into(),
		data: Vec::new(),
	}.sign(secret, None), Some(Condition::Number(2)));
	let tx1 = PendingTransaction::new(Transaction {
		nonce: 1.into(),
		gas_price: 0.into(),
		gas: 21000.into(),
		action: Action::Call(Address::default()),
		value: 0.into(),
		data: Vec::new(),
	}.sign(secret, None), None);
	let client = generate_dummy_client(1);

	client.miner().import_own_transaction(&*client, tx0).unwrap();
	client.miner().import_own_transaction(&*client, tx1).unwrap();
	assert_eq!(0, client.ready_transactions().len());
	assert_eq!(0, client.miner().ready_transactions(&*client).len());
	push_blocks_to_client(&client, 53, 2, 2);
	client.flush_queue();
	assert_eq!(2, client.ready_transactions().len());
	assert_eq!(2, client.miner().ready_transactions(&*client).len());
}

#[test]
fn transaction_proof() {
	use ::client::ProvingBlockChainClient;

	let client = generate_dummy_client(0);
	let address = Address::random();
	let test_spec = Spec::new_test();
	for _ in 0..20 {
		let mut b = client.prepare_open_block(Address::default(), (3141562.into(), 31415620.into()), vec![]);
		b.block_mut().state_mut().add_balance(&address, &5.into(), CleanupMode::NoEmpty).unwrap();
		b.block_mut().state_mut().commit().unwrap();
		let b = b.close_and_lock().seal(&*test_spec.engine, vec![]).unwrap();
		client.import_sealed_block(b).unwrap(); // account change is in the journal overlay
	}

	let transaction = Transaction {
		nonce: 0.into(),
		gas_price: 0.into(),
		gas: 21000.into(),
		action: Action::Call(Address::default()),
		value: 5.into(),
		data: Vec::new(),
	}.fake_sign(address);

	let proof = client.prove_transaction(transaction.clone(), BlockId::Latest).unwrap().1;
	let backend = state::backend::ProofCheck::new(&proof);

	let mut factories = ::factory::Factories::default();
	factories.accountdb = ::account_db::Factory::Plain; // raw state values, no mangled keys.
	let root = *client.best_block_header().state_root();

	let mut state = State::from_existing(backend, root, 0.into(), factories.clone()).unwrap();
	Executive::new(&mut state, &client.latest_env_info(), test_spec.engine.machine())
		.transact(&transaction, TransactOptions::with_no_tracing().dont_check_nonce()).unwrap();

	assert_eq!(state.balance(&Address::default()).unwrap(), 5.into());
	assert_eq!(state.balance(&address).unwrap(), 95.into());
}
