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

use ethereum_types::{Address, U256};
use client::{BlockId, Client, BlockChainClient, CallContract};

// Contract ABI generated from forked simple_casper (to use latest vyper) at https://github.com/ascjones/casper/blob/80e08b13db1f096f2652e7e4330d4c65af8d13d2/casper/contracts/simple_casper.v.py
// Compiled using https://vyper.online/ 
// Also, decimal10 types were replaced with int256, in order for this macro to work. Issue in ethabi: https://github.com/paritytech/ethabi/issues/93
use_contract!(simple_casper_contract, "SimpleCasper", "res/contracts/simple_casper.json");

pub type Epoch = U256;
pub type I128 = U256; 		// Marker type for int128 in casper contract
pub type Decimal = U256; 	// Marker type for decimal10 in casper contract
pub type Error = String; 	// TODO: [aj] should we use EngineError or more specialised error?

pub type ExecuteCasperTransaction<'a> = FnMut(Address, Vec<u8>) -> Result<(), String> + 'a;

// Transactions for creating casper contract dependencies
// Copied from https://github.com/karlfloersch/pyethereum/blob/develop/ethereum/hybrid_casper/casper_initiating_transactions.py
// const VIPER_RLP_DECODER_TX: &'static str = "f9035b808506fc23ac0083045f788080b903486103305660006109ac5260006109cc527f0100000000000000000000000000000000000000000000000000000000000000600035046109ec526000610a0c5260006109005260c06109ec51101515585760f86109ec51101561006e5760bf6109ec510336141558576001610a0c52610098565b60013560f76109ec51036020035260005160f66109ec510301361415585760f66109ec5103610a0c525b61022060016064818352015b36610a0c511015156100b557610291565b7f0100000000000000000000000000000000000000000000000000000000000000610a0c5135046109ec526109cc5160206109ac51026040015260016109ac51016109ac5260806109ec51101561013b5760016109cc5161044001526001610a0c516109cc5161046001376001610a0c5101610a0c5260216109cc51016109cc52610281565b60b86109ec5110156101d15760806109ec51036109cc51610440015260806109ec51036001610a0c51016109cc51610460013760816109ec5114156101ac5760807f01000000000000000000000000000000000000000000000000000000000000006001610a0c5101350410151558575b607f6109ec5103610a0c5101610a0c5260606109ec51036109cc51016109cc52610280565b60c06109ec51101561027d576001610a0c51013560b76109ec510360200352600051610a2c526038610a2c5110157f01000000000000000000000000000000000000000000000000000000000000006001610a0c5101350402155857610a2c516109cc516104400152610a2c5160b66109ec5103610a0c51016109cc516104600137610a2c5160b66109ec5103610a0c510101610a0c526020610a2c51016109cc51016109cc5261027f565bfe5b5b5b81516001018083528114156100a4575b5050601f6109ac511115155857602060206109ac5102016109005260206109005103610a0c5261022060016064818352015b6000610a0c5112156102d45761030a565b61090051610a0c516040015101610a0c51610900516104400301526020610a0c5103610a0c5281516001018083528114156102c3575b50506109cc516109005101610420526109cc5161090051016109005161044003f35b61000461033003610004600039610004610330036000f31b2d4f";
// const SIG_HASHER_TX: &'static str = "f9016d808506fc23ac0083026a508080b9015a6101488061000e6000396101565660007f01000000000000000000000000000000000000000000000000000000000000006000350460f8811215610038576001915061003f565b60f6810391505b508060005b368312156100c8577f01000000000000000000000000000000000000000000000000000000000000008335048391506080811215610087576001840193506100c2565b60b881121561009d57607f8103840193506100c1565b60c08112156100c05760b68103600185013560b783036020035260005101840193505b5b5b50610044565b81810360388112156100f4578060c00160005380836001378060010160002060e052602060e0f3610143565b61010081121561010557600161011b565b6201000081121561011757600261011a565b60035b5b8160005280601f038160f701815382856020378282600101018120610140526020610140f350505b505050505b6000f31b2d4f";
// const PURITY_CHECKER_TX: &'static str = "f90467808506fc23ac00830583c88080b904546104428061000e60003961045056600061033f537c0100000000000000000000000000000000000000000000000000000000600035047f80010000000000000000000000000000000000000030ffff1c0e00000000000060205263a1903eab8114156103f7573659905901600090523660048237600435608052506080513b806020015990590160009052818152602081019050905060a0526080513b600060a0516080513c6080513b8060200260200159905901600090528181526020810190509050610100526080513b806020026020015990590160009052818152602081019050905061016052600060005b602060a05103518212156103c957610100601f8360a051010351066020518160020a161561010a57fe5b80606013151561011e57607f811315610121565b60005b1561014f5780607f036101000a60018460a0510101510482602002610160510152605e8103830192506103b2565b60f18114801561015f5780610164565b60f282145b905080156101725780610177565b60f482145b9050156103aa5760028212151561019e5760606001830360200261010051015112156101a1565b60005b156101bc57607f6001830360200261010051015113156101bf565b60005b156101d157600282036102605261031e565b6004821215156101f057600360018303602002610100510151146101f3565b60005b1561020d57605a6002830360200261010051015114610210565b60005b1561022b57606060038303602002610100510151121561022e565b60005b1561024957607f60038303602002610100510151131561024c565b60005b1561025e57600482036102605261031d565b60028212151561027d57605a6001830360200261010051015114610280565b60005b1561029257600282036102605261031c565b6002821215156102b157609060018303602002610100510151146102b4565b60005b156102c657600282036102605261031b565b6002821215156102e65760806001830360200261010051015112156102e9565b60005b156103035760906001830360200261010051015112610306565b60005b1561031857600282036102605261031a565bfe5b5b5b5b5b604060405990590160009052600081526102605160200261016051015181602001528090502054156103555760016102a052610393565b60306102605160200261010051015114156103755760016102a052610392565b60606102605160200261010051015114156103915760016102a0525b5b5b6102a051151561039f57fe5b6001830192506103b1565b6001830192505b5b8082602002610100510152600182019150506100e0565b50506001604060405990590160009052600081526080518160200152809050205560016102e05260206102e0f35b63c23697a8811415610440573659905901600090523660048237600435608052506040604059905901600090526000815260805181602001528090502054610300526020610300f35b505b6000f31b2d4f";

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

	// fn transact_null_sender(&self, data: Option<Vec<u8>>) {
		
	// }

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
            .call(&|data| self.client.call_contract(BlockId::Latest, self.address, data))
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

	fn initialize_epoch(&self, epoch: I128, exec: &mut ExecuteCasperTransaction) -> Result<(), Error> {
		let init_epoch = self.casper.functions().initialize_epoch();
		exec(self.address, init_epoch.input(epoch))
	}
}

#[cfg(test)]
mod test {
	use super::{SimpleCasperContract};
	use ethabi::{encode, Token};
	use ethereum_types::{Address, U256};
	use client::{BlockId, CallContract, BlockInfo, ImportSealedBlock, PrepareOpenBlock};
	use spec::Spec;
	use rustc_hex::ToHex;
	use test_helpers::generate_dummy_client_with_spec_and_accounts;
	use transaction::{Action, SignedTransaction, PendingTransaction, Transaction};
	use miner::MinerService;

	const EPOCH_LENGTH: u32 = 10;
	const CASPER_ADDRESS: &'static str = "bd832b0cd3291c39ef67691858f35c71dfb3bf21"; 

	// using this for now just to generate the constructor bytecode to be appended to the contract bytecode in casper_ffg.json
	// just run with cargo test -- --nocapture
	#[test]
	fn generate_casper_constructor_bytecode() {
		// casper constructor
		// 		def __init__(
		//         epoch_length: int128, withdrawal_delay: int128, dynasty_logout_delay: int128,
		//         owner: address, sighasher: address, purity_checker: address,
		//         base_interest_factor: decimal, base_penalty_factor: decimal,
		// min_deposit_size: wei_value):

		let epoch_length = Token::Int(EPOCH_LENGTH.into());
		let withdrawal_delay = Token::Int(2u32.into());
		let dynasty_logout_delay = Token::Int(3u32.into());
		let owner = Token::Address("0000000000000000000000000000000000000004".into());
		let sighasher = Token::Address("0000000000000000000000000000000000000005".into());
		let purity_checker = Token::Address("0000000000000000000000000000000000000006".into());
		let base_interest_factor = Token::Int(7u32.into()); // int instead of decimal
		let base_penalty_factor = Token::Int(8u32.into()); // todo: convert decimal value to int equivalent
		let min_deposit_size = Token::Uint(9u32.into());

		let encoded = encode(&[epoch_length, withdrawal_delay, dynasty_logout_delay, owner, sighasher, purity_checker, base_interest_factor, base_penalty_factor, min_deposit_size]);
		println!("ENCODED: '{:?}'", encoded.to_hex());

		// result: append after 36000f3 in casper_ffg.json
		// 000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000009
	}

	fn setup() -> SimpleCasperContract {
		let client = generate_dummy_client_with_spec_and_accounts(
			Spec::new_test_hybrid_casper,
			None,
		);

		SimpleCasperContract::new(
			CASPER_ADDRESS.into(),
			client.clone(),
		)
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
	fn init_first_epoch() {
		let casper = setup();
		let client = casper.client.clone();

		let current_epoch = casper.current_epoch().unwrap();
		let epoch_length = casper.epoch_length().unwrap();

		assert_eq!(Ok(0.into()), casper.current_epoch());
		assert_eq!(Ok(1.into()), casper.next_validator_index());

		// new_epoch()
		let current_block = client.best_block_header().number();
		let block_count = epoch_length * (current_epoch + 1.into()) - current_block.into();

		// add blocks - is this the best way?
		for _ in 0u32..From::from(block_count) {
			let mut b = client.prepare_open_block(Address::default(), (3141562.into(), 31415620.into()), vec![]);
			// b.block_mut().state_mut().add_balance(&address, &5.into(), CleanupMode::NoEmpty).unwrap();
			b.block_mut().state_mut().commit().unwrap();
			let b = b.close_and_lock().seal(&*client.engine(), vec![]).unwrap();
			client.import_sealed_block(b).unwrap();
		}

		println!("Current block {} before init", client.best_block_header().number());

		let mut exec = |to, data| {
			let from = Address::default(); // todo: null sender????
			let transaction = Transaction {
				nonce: U256::default(),
				action: Action::Call(to),
				gas: U256::from(3_141_562),  // Sames as block gas limit (copied from ethereumj). todo: what should it be?
				gas_price: U256::default(),
				value: U256::zero(),
				data: data,
			}.fake_sign(from);
			client.miner().import_own_transaction(&*client, transaction.into())
				.map_err(|e| e.to_string())	
		};

		let res = casper.initialize_epoch(1.into(), &mut exec);
		::client::EngineClient::update_sealing(&*client);

		// check contract precondition
		let current_block : U256 = client.best_block_header().number().into();
		let computed_current_epoch = current_block / epoch_length;

		println!("Current block {}, epoch length {}, computed current epoch {}", 
			current_block, epoch_length, computed_current_epoch);
		
		assert_eq!(Ok(()), res);

		assert_eq!(Ok(0.into()), casper.dynasty());
		assert_eq!(Ok(1.into()), casper.next_validator_index());
		assert_eq!(Ok(computed_current_epoch), casper.current_epoch());
	}
}

// VALIDATOR COMMANDS
// initialize_epoch
// https://github.com/ethereum/casper/blob/master/casper/contracts/simple_casper.v.py#L248

// deposit 
// https://github.com/ethereum/casper/blob/master/casper/contracts/simple_casper.v.py#L281

// logout
// https://github.com/ethereum/casper/blob/master/casper/contracts/simple_casper.v.py#L302

// withdraw
// https://github.com/ethereum/casper/blob/master/casper/contracts/simple_casper.v.py#L338

// vote
// https://github.com/ethereum/casper/blob/master/casper/contracts/simple_casper.v.py#L370

// slash
// https://github.com/ethereum/casper/blob/master/casper/contracts/simple_casper.v.py#L443