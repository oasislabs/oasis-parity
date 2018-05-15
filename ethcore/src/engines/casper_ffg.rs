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

use std::sync::Arc;

use client::{BlockId, Client, CallContract};
use ethereum_types::{Address, U256};
use executive::contract_address;
use transaction::{SignedTransaction, Transaction, UnverifiedTransaction};
use vm::CreateContractAddress;
use rustc_hex::FromHex;

// Contract bytecode and ABI generated from https://github.com/ethereum/casper/v0.1.0 // todo
// This uses vyper compiler v0.4.0 which won't build from the vyper repo, but will work from within the casper repo.
// 1) Clone casper repo
// 2) Setup virtualenv for casper
// 3) pip install requirementes
// 4) py test
// 5) cd contracts && vyper simple_casper.v.py

// Also, decimal10 types were replaced with int256, in order for this macro to work. Issue in ethabi: https://github.com/paritytech/ethabi/issues/93
const CASPER_CONTRACT: &'static str = include_str!("../../res/contracts/simple_casper.evm");

use_contract!(simple_casper_contract, "SimpleCasper", "res/contracts/simple_casper.json");

pub type Epoch = U256;
pub type I128 = U256; 		// Marker type for int128 in casper contract
pub type Decimal = U256; 	// Marker type for decimal10 in casper contract
pub type Error = String; 	// TODO: [aj] should we use EngineError or more specialised error?

pub type ExecuteCasperTransaction<'a> = Fn(Address, Vec<u8>) -> Result<(), String> + 'a;

// Transactions for creating casper contract dependencies
// Copied from https://github.com/ethereum/casper/blob/v0.1.0/tests/conftest.py
const VIPER_RLP_DECODER_TX: &'static str = "f9035b808506fc23ac0083045f788080b903486103305660006109ac5260006109cc527f0100000000000000000000000000000000000000000000000000000000000000600035046109ec526000610a0c5260006109005260c06109ec51101515585760f86109ec51101561006e5760bf6109ec510336141558576001610a0c52610098565b60013560f76109ec51036020035260005160f66109ec510301361415585760f66109ec5103610a0c525b61022060016064818352015b36610a0c511015156100b557610291565b7f0100000000000000000000000000000000000000000000000000000000000000610a0c5135046109ec526109cc5160206109ac51026040015260016109ac51016109ac5260806109ec51101561013b5760016109cc5161044001526001610a0c516109cc5161046001376001610a0c5101610a0c5260216109cc51016109cc52610281565b60b86109ec5110156101d15760806109ec51036109cc51610440015260806109ec51036001610a0c51016109cc51610460013760816109ec5114156101ac5760807f01000000000000000000000000000000000000000000000000000000000000006001610a0c5101350410151558575b607f6109ec5103610a0c5101610a0c5260606109ec51036109cc51016109cc52610280565b60c06109ec51101561027d576001610a0c51013560b76109ec510360200352600051610a2c526038610a2c5110157f01000000000000000000000000000000000000000000000000000000000000006001610a0c5101350402155857610a2c516109cc516104400152610a2c5160b66109ec5103610a0c51016109cc516104600137610a2c5160b66109ec5103610a0c510101610a0c526020610a2c51016109cc51016109cc5261027f565bfe5b5b5b81516001018083528114156100a4575b5050601f6109ac511115155857602060206109ac5102016109005260206109005103610a0c5261022060016064818352015b6000610a0c5112156102d45761030a565b61090051610a0c516040015101610a0c51610900516104400301526020610a0c5103610a0c5281516001018083528114156102c3575b50506109cc516109005101610420526109cc5161090051016109005161044003f35b61000461033003610004600039610004610330036000f31b2d4f";
const SIG_HASHER_TX: &'static str = "f9016d808506fc23ac0083026a508080b9015a6101488061000e6000396101565660007f01000000000000000000000000000000000000000000000000000000000000006000350460f8811215610038576001915061003f565b60f6810391505b508060005b368312156100c8577f01000000000000000000000000000000000000000000000000000000000000008335048391506080811215610087576001840193506100c2565b60b881121561009d57607f8103840193506100c1565b60c08112156100c05760b68103600185013560b783036020035260005101840193505b5b5b50610044565b81810360388112156100f4578060c00160005380836001378060010160002060e052602060e0f3610143565b61010081121561010557600161011b565b6201000081121561011757600261011a565b60035b5b8160005280601f038160f701815382856020378282600101018120610140526020610140f350505b505050505b6000f31b2d4f";
const PURITY_CHECKER_TX: &'static str = "f90467808506fc23ac00830583c88080b904546104428061000e60003961045056600061033f537c0100000000000000000000000000000000000000000000000000000000600035047f80010000000000000000000000000000000000000030ffff1c0e00000000000060205263a1903eab8114156103f7573659905901600090523660048237600435608052506080513b806020015990590160009052818152602081019050905060a0526080513b600060a0516080513c6080513b8060200260200159905901600090528181526020810190509050610100526080513b806020026020015990590160009052818152602081019050905061016052600060005b602060a05103518212156103c957610100601f8360a051010351066020518160020a161561010a57fe5b80606013151561011e57607f811315610121565b60005b1561014f5780607f036101000a60018460a0510101510482602002610160510152605e8103830192506103b2565b60f18114801561015f5780610164565b60f282145b905080156101725780610177565b60f482145b9050156103aa5760028212151561019e5760606001830360200261010051015112156101a1565b60005b156101bc57607f6001830360200261010051015113156101bf565b60005b156101d157600282036102605261031e565b6004821215156101f057600360018303602002610100510151146101f3565b60005b1561020d57605a6002830360200261010051015114610210565b60005b1561022b57606060038303602002610100510151121561022e565b60005b1561024957607f60038303602002610100510151131561024c565b60005b1561025e57600482036102605261031d565b60028212151561027d57605a6001830360200261010051015114610280565b60005b1561029257600282036102605261031c565b6002821215156102b157609060018303602002610100510151146102b4565b60005b156102c657600282036102605261031b565b6002821215156102e65760806001830360200261010051015112156102e9565b60005b156103035760906001830360200261010051015112610306565b60005b1561031857600282036102605261031a565bfe5b5b5b5b5b604060405990590160009052600081526102605160200261016051015181602001528090502054156103555760016102a052610393565b60306102605160200261010051015114156103755760016102a052610392565b60606102605160200261010051015114156103915760016102a0525b5b5b6102a051151561039f57fe5b6001830192506103b1565b6001830192505b5b8082602002610100510152600182019150506100e0565b50506001604060405990590160009052600081526080518160200152809050205560016102e05260206102e0f35b63c23697a8811415610440573659905901600090523660048237600435608052506040604059905901600090526000815260805181602001528090502054610300526020610300f35b505b6000f31b2d4f";

pub struct CasperContractParams {
    epoch_length: usize,
    withdrawal_delay: u64,
    dynasty_logout_delay: u64,
    base_interest_factor: f64,
    base_penalty_factor: f64,
    min_deposit_size_eth: u64,
}

/// Convert a float to a U256, this can be replaced when we have a type for vyper decimal10/fixedMofN
fn float_to_int(v: f64) -> U256 {
	// todo: [AJ] check for inputs > MAX / 10 ^ 10
	let x = v * 10.0_f64.powi(10);
	if x < 1.0 {
		panic!("Max 10 decimal place precision");
	}
	U256::from(x as i64)
}

// pub struct CasperParams {
// 	contract_params: CasperContractParams,
// 	null_sender: Address,
// }

/// A client for the CasperFFG contract simple_casper.v.py
pub struct SimpleCasperContract {
    address: Address,
    casper: simple_casper_contract::SimpleCasper,
	client: Arc<Client>,
}

impl SimpleCasperContract {
    pub fn new(address: Address, client: Arc<Client>) -> SimpleCasperContract {
        SimpleCasperContract {
            address,
           	casper: simple_casper_contract::SimpleCasper::default(),
			client,
        }
    }

	fn epoch_length(&self) -> Result<I128, Error> {
		self.casper.functions()
			.epoch_length()
            .call(&|data| self.client.call_contract(BlockId::Latest, self.address, data))
			.map_err(|e| e.to_string())
	}

	fn withdrawal_delay(&self) -> Result<I128, Error> {
        self.casper.functions()
            .withdrawal_delay()
            .call(&|data| self.client.call_contract(BlockId::Latest, self.address, data))
			.map_err(|e| e.to_string())
	}

	fn dynasty_logout_delay(&self) -> Result<I128, Error> {
        self.casper.functions()
            .dynasty_logout_delay()
            .call(&|data| self.client.call_contract(BlockId::Latest, self.address, data))
			.map_err(|e| e.to_string())
	}

	fn base_interest_factor(&self) -> Result<Decimal, Error> {
        self.casper.functions()
            .base_interest_factor()
            .call(&|data| self.client.call_contract(BlockId::Latest, self.address, data))
			.map_err(|e| e.to_string())
	}

	fn base_penalty_factor(&self) -> Result<Decimal, Error> {
        self.casper.functions()
            .base_penalty_factor()
            .call(&|data| self.client.call_contract(BlockId::Latest, self.address, data))
			.map_err(|e| e.to_string())
	}

    fn current_epoch(&self) -> Result<Epoch, Error> {
        self.casper.functions()
            .current_epoch()
            .call(&|data| {
				let res = self.client.call_contract(BlockId::Latest, self.address, data);
				println!("Current epoch {:?}", res);
				res
			})
			.map_err(|e| e.to_string())
    }

	fn next_validator_index(&self) -> Result<I128, Error> {
        self.casper.functions()
            .next_validator_index()
            .call(&|data| self.client.call_contract(BlockId::Latest, self.address, data))
			.map_err(|e| e.to_string())
	}

	fn dynasty(&self) -> Result<I128, Error> {
        self.casper.functions()
            .dynasty()
            .call(&|data| self.client.call_contract(BlockId::Latest, self.address, data))
			.map_err(|e| e.to_string())
	}

	fn initialize_epoch(&self, epoch: I128, transact: &ExecuteCasperTransaction) -> Result<(), Error> {
		let init_epoch = self.casper.functions().initialize_epoch();
		transact(self.address, init_epoch.input(epoch))
	}
}

pub fn casper_initiating_transactions(params: &CasperContractParams, start_nonce: U256) -> (Vec<SignedTransaction>, Address) {
	fn decode_tx(hex: &str) -> (SignedTransaction, Address) {
		let bytes = ::rustc_hex::FromHex::from_hex(hex).expect("hardcoded transaction should be valid hex");
		let unverified_tx : UnverifiedTransaction = ::rlp::decode(&bytes);
		let unsigned_tx = unverified_tx.as_unsigned().clone();
		let nonce = unsigned_tx.nonce;
		let signed_tx = unsigned_tx.null_sign(1); // todo: [AJ] check chain_id should = 1 (also on fund tx)
		let (addr,_) = contract_address(CreateContractAddress::FromSenderAndNonce, &signed_tx.sender(), &nonce, &[]);
		(signed_tx, addr)
	}

	let (viper_rlp_decoder_tx,_) = decode_tx(VIPER_RLP_DECODER_TX);
	let (sig_hasher_tx, sig_hasher_addr) = decode_tx(SIG_HASHER_TX);
	let (purity_checker_tx, purity_checker_addr) = decode_tx(PURITY_CHECKER_TX);

	let mut txs = Vec::new();
	let mut nonce = start_nonce;
	let gas_price = U256::from(25_000_000_000);

	for tx in [viper_rlp_decoder_tx, sig_hasher_tx, purity_checker_tx].iter() {
		let fund_tx = Transaction {
			nonce: nonce,
			action: tx.action.clone(),
			gas: U256::from(90_000),
			gas_price,
			value: tx.gas * tx.gas_price + tx.value,
			data: vec![],
		}.null_sign(1);
		txs.push(tx.clone());
		txs.push(fund_tx);
		nonce = nonce + 1.into();
	}

	let constructor_code = CASPER_CONTRACT.from_hex().expect("Casper contract code is valid");
	let contract = simple_casper_contract::SimpleCasper::default();
	// todo: use i128 here instead with new rust?
	let min_deposit_size_wei = U256::from(params.min_deposit_size_eth) * U256::from(10).pow(U256::from(18));
	let data = contract.constructor(
		constructor_code,
		params.epoch_length,
		params.withdrawal_delay,
		params.dynasty_logout_delay,
		sig_hasher_addr,
		purity_checker_addr,
		// todo: [AJ] convert f64s above into abi compatible ints
		float_to_int(params.base_interest_factor),
		float_to_int(params.base_penalty_factor),
		min_deposit_size_wei,
	);
	let casper_deploy_tx = Transaction {
		nonce,
		action: Action::Create,
		gas: U256::from(5_000_000),
		gas_price,
		value: U256::from(0),
		data,
	}.null_sign(1);
	txs.push(casper_deploy_tx);
	let (casper_addr,_) = contract_address(CreateContractAddress::FromSenderAndNonce, &casper_deploy_tx.sender(), &nonce, &[]);
	txs, casper_addr
	// let sig_hasher_tx: UnverifiedTransaction =
    // o = []
    // nonce = starting_nonc
    // # Create transactions for instantiating RLP decoder, sig hasher and purity checker, plus transactions for feeding the
    // # one-time accounts that generate those transactions
    // for tx in (viper_rlp_decoder_tx, sig_hasher_tx, purity_checker_tx):
    //     o.append(Transaction(nonce, gasprice, 90000, tx.sender, tx.startgas * tx.gasprice + tx.value, '').sign(sender_privkey))
    //     o.append(tx)
    //     nonce += 1
    // # Casper initialization transaction
    // params = [config["EPOCH_LENGTH"], config["WITHDRAWAL_DELAY"], config["OWNER"], sig_hasher_address,
    //           purity_checker_address, config["BASE_INTEREST_FACTOR"], config["BASE_PENALTY_FACTOR"],
    //           config["MIN_DEPOSIT_SIZE"]]
    // # Casper deploy bytecode
    // casper_deploy_bytecode = casper_bytecode + casper_ct.encode_constructor_arguments(params)
    // casper_deploy_tx = Transaction(nonce, gasprice, 5000000, b'', 0, casper_deploy_bytecode).sign(sender_privkey)
    // # Return list of transactions and Casper address
    // return o + [casper_deploy_tx], casper_deploy_tx.creates
}

#[cfg(test)]
mod test {
	use std::sync::Arc;
	use super::*;
	use ethabi::{encode, Token};
	use ethereum_types::{Address, U256};
	use client::{Client, BlockInfo, ImportSealedBlock, PrepareOpenBlock};
	use spec::Spec;
	use rustc_hex::ToHex;
	use test_helpers::generate_dummy_client_with_spec_and_accounts;
	use transaction::{Action, Transaction};
	use miner::MinerService;

	const EPOCH_LENGTH: u32 = 10;

	fn setup() -> SimpleCasperContract {
		let params = CasperContractParams {
			epoch_length: 50,
			withdrawal_delay: 15000,
			dynasty_logout_delay: 700,
			base_interest_factor: 7e-3,
			base_penalty_factor: 2e-7,
			min_deposit_size_eth: 1500,
		};

		let (txs, casper_addr) = casper_initiating_transactions(&params, 0.into());

		let client = generate_dummy_client_with_spec_and_accounts(
			Spec::new_test_hybrid_casper,
			None,
		);

		// run init txs - todo: extract function
		for tx in txs {

		}

		// from pyethereum
	// 	state.gas_limit = 10**8
    // for tx in init_txs:
    //     state.set_balance(utils.privtoaddr(config.casper_config['SENDER']), 15**18)
    //     success, output = apply_transaction(state, tx)
    //     assert success
    //     state.gas_used = 0
    //     state.set_balance(utils.privtoaddr(config.casper_config['SENDER']), 0)
    //     state.set_balance(casper_address, 10**25)
    // consensus.initialize(state)

		// from ethereumj
	//  txs.forEach((tx) -> {
    //         // We need money!
    //         track.addBalance(NULL_SIGN_SENDER.getAddress(), BigInteger.valueOf(15).pow(18));

    //         Repository txTrack = track.startTracking();
    //         TransactionExecutor executor = createTransactionExecutor(tx, coinbase, txTrack, block, 0);

    //         executor.init();
    //         executor.execute();
    //         executor.go();
    //         executor.finalization();

    //         byte[] contractAddress = executor.getReceipt().getTransaction().getContractAddress();
    //         if (contractAddress != null) {
    //             logger.info("Casper init: contract deployed at {}, tx: [{}]", Hex.toHexString(contractAddress), tx);
    //         }
    //         if (!executor.getReceipt().isSuccessful()) {
    //             logger.error("Casper init failed on tx [{}], receipt [{}], breaking", tx, executor.getReceipt());
    //             throw new RuntimeException("Casper initialization transactions on 1st block failed");
    //         }

    //         txTrack.commit();
    //         BigInteger restBalance = track.getBalance(NULL_SIGN_SENDER.getAddress());
    //         track.addBalance(NULL_SIGN_SENDER.getAddress(), restBalance.negate());
    //         track.addBalance(casperAddress, track.getBalance(casperAddress).negate());
    //         track.addBalance(casperAddress, BigInteger.valueOf(10).pow(25));
    //     });

		SimpleCasperContract::new(
			casper_addr,
			client.clone(),
		)
	}

	fn exec_casper<'a>(client: Arc<Client>) -> Box<ExecuteCasperTransaction<'a>> {
		let exec = move |to, data| {
			let from = Address::default(); // todo: null sender????
			let transaction = Transaction {
				nonce: U256::default(),
				action: Action::Call(to),
				gas: 3_000_000.into(), // todo: should work with 0 gas
				gas_price: U256::default(),
				value: U256::zero(),
				data: data,
			}.fake_sign(from);
			client.miner().import_own_transaction(&*client, transaction.into())
				.map_err(|e| e.to_string())
		};
		Box::new(exec)
	}

	#[test]
	fn constructor_parameters_initialized() {
		let casper = setup();

		assert_eq!(Ok(EPOCH_LENGTH.into()), casper.epoch_length());
		assert_eq!(Ok(2.into()), casper.withdrawal_delay());
		assert_eq!(Ok(3.into()), casper.dynasty_logout_delay());
		assert_eq!(Ok(7.into()), casper.base_interest_factor());
		assert_eq!(Ok(8.into()), casper.base_penalty_factor());
	}

	#[test]
	// https://github.com/ethereum/casper/blob/v0.1.0/casper/contracts/simple_casper.v.py#L364
	fn init_first_epoch() {
		::env_logger::init().ok();

		let casper = setup();
		let client = casper.client.clone();

		let current_epoch = casper.current_epoch().unwrap();
		let epoch_length = casper.epoch_length().unwrap();

		assert_eq!(Ok(0.into()), casper.current_epoch());
		assert_eq!(Ok(1.into()), casper.next_validator_index());

		let current_block = client.best_block_header().number();
		let block_count = epoch_length * (current_epoch + 1.into()) - current_block.into();

		// add blocks - is this the best way?
		for _ in 0u32..From::from(block_count) {
			let mut b = client.prepare_open_block(Address::default(), (3141562.into(), 31415620.into()), vec![]);
			b.block_mut().state_mut().commit().unwrap();
			let b = b.close_and_lock().seal(&*client.engine(), vec![]).unwrap();
			client.import_sealed_block(b).unwrap();
		}

		let _event = casper.casper.events().epoch();
		let exec = exec_casper(client.clone());

		let res = casper.initialize_epoch(1.into(), &*exec); // &mut exec);

		// check contract precondition
		let current_block : U256 = client.best_block_header().number().into();
		let computed_current_epoch = current_block / epoch_length;

		assert_eq!(Ok(()), res);

		assert_eq!(Ok(0.into()), casper.dynasty());
		assert_eq!(Ok(1.into()), casper.next_validator_index());
		assert_eq!(Ok(computed_current_epoch), casper.current_epoch());
	}

	// todo: deposit - look at some tests from https://github.com/ethereum/casper/blob/master/tests/test_deposit.py
	// #[test]
	// // https://github.com/ethereum/casper/blob/v0.1.0/casper/contracts/simple_casper.v.py#L364
	// fn deposit() {
	// 	::env_logger::init().ok();

	// 	let casper = setup();
	// 	let client = casper.client.clone();
	// }
}

// VALIDATOR COMMANDS

// logout
// https://github.com/ethereum/casper/blob/master/casper/contracts/simple_casper.v.py#L302

// withdraw
// https://github.com/ethereum/casper/blob/master/casper/contracts/simple_casper.v.py#L338

// vote
// https://github.com/ethereum/casper/blob/master/casper/contracts/simple_casper.v.py#L370

// slash
// https://github.com/ethereum/casper/blob/master/casper/contracts/simple_casper.v.py#L443
