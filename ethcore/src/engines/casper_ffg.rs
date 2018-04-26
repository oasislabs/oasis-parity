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
use client::{BlockId, Client, CallContract};

// Contract ABI generated from forked simple_casper (to use latest vyper) at https://github.com/ascjones/casper/blob/80e08b13db1f096f2652e7e4330d4c65af8d13d2/casper/contracts/simple_casper.v.py
// Compiled using https://vyper.online/ 
// Also, decimal10 types were replaced with int256, in order for this macro to work. Issue in ethabi: https://github.com/paritytech/ethabi/issues/93
use_contract!(simple_casper_contract, "SimpleCasper", "res/contracts/simple_casper.json");

pub type Epoch = U256;
pub type I128 = U256; 		// Marker type for int128 in casper contract
pub type Decimal = U256; 	// Marker type for decimal10 in casper contract
pub type Error = String; 	// TODO: [aj] should we use EngineError or more specialised error?

/// A client for the CasperFFG contract simple_casper.v.py
pub struct SimpleCasperContract {
    address: Address,
    simple_casper_contract: simple_casper_contract::SimpleCasper,
	client: Arc<Client>,
}

impl SimpleCasperContract {
    pub fn new(address: Address, client: Arc<Client>) -> SimpleCasperContract {
        SimpleCasperContract {
            address,
            simple_casper_contract: simple_casper_contract::SimpleCasper::default(),
			client,
        }
    }

	// pub fn public_creation_transaction(&self, block: BlockId, source: &SignedTransaction, validators: &[Address], gas_price: U256) -> Result<(Transaction, Option<Address>), Error> {
	// 	if let Action::Call(_) = source.action {
	// 		bail!(ErrorKind::BadTransactonType);
	// 	}
	// 	let sender = source.sender();
	// 	let state = self.client.state_at(block).ok_or(ErrorKind::StatePruned)?;
	// 	let nonce = state.nonce(&sender)?;
	// 	let executed = self.execute_private(source, TransactOptions::with_no_tracing(), block)?;
	// 	let gas: u64 = 650000 +
	// 		validators.len() as u64 * 30000 +
	// 		executed.code.as_ref().map_or(0, |c| c.len() as u64) * 8000 +
	// 		executed.state.len() as u64 * 8000;
	// 	Ok((Transaction {
	// 		nonce: nonce,
	// 		action: Action::Create,
	// 		gas: gas.into(),
	// 		gas_price: gas_price,
	// 		value: source.value,
	// 		data: Self::generate_constructor(validators, executed.code.unwrap_or_default(), executed.state)
	// 	},
	// 	executed.contract_address))
	// 

	fn epoch_length(&self) -> Result<I128, Error> {
		self.simple_casper_contract.functions()
			.epoch_length()
			.call(&|data| self.client.call_contract(BlockId::Latest, self.address, data))
			.map_err(|e| e.to_string())
	}

	fn withdrawal_delay(&self) -> Result<I128, Error> {
        self.simple_casper_contract.functions()
            .withdrawal_delay()
            .call(&|data| self.client.call_contract(BlockId::Latest, self.address, data))
			.map_err(|e| e.to_string())
	}

	fn dynasty_logout_delay(&self) -> Result<I128, Error> {
        self.simple_casper_contract.functions()
            .dynasty_logout_delay()
            .call(&|data| self.client.call_contract(BlockId::Latest, self.address, data))
			.map_err(|e| e.to_string())
	}

	fn base_interest_factor(&self) -> Result<Decimal, Error> {
        self.simple_casper_contract.functions()
            .base_interest_factor()
            .call(&|data| self.client.call_contract(BlockId::Latest, self.address, data))
			.map_err(|e| e.to_string())
	}

	fn base_penalty_factor(&self) -> Result<Decimal, Error> {
        self.simple_casper_contract.functions()
            .base_penalty_factor()
            .call(&|data| self.client.call_contract(BlockId::Latest, self.address, data))
			.map_err(|e| e.to_string())
	}

    fn current_epoch(&self) -> Result<Epoch, Error> {
        self.simple_casper_contract.functions()
            .current_epoch()
            .call(&|data| self.client.call_contract(BlockId::Latest, self.address, data))
			.map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod test {
	use super::{SimpleCasperContract};
	use ethabi::{encode, Token};
	use client::{BlockId, CallContract};
	use spec::Spec;
	use rustc_hex::ToHex;
	use test_helpers::generate_dummy_client_with_spec_and_accounts;

	// "bd832b0cd3291c39ef67691858f35c71dfb3bf21" // todo: casper address const

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

		let epoch_length = Token::Int(1u32.into());
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

		// result: pasted after 36000f3 in casper_ffg.json
		// 000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000009
	}

	#[test]
	fn simple_casper_contract() {
		let client = generate_dummy_client_with_spec_and_accounts(
			Spec::new_test_hybrid_casper,
			None,
		);

		let casper = SimpleCasperContract::new(
			"bd832b0cd3291c39ef67691858f35c71dfb3bf21".into(),
			client.clone(),
		);

		// constructor args
		assert_eq!(Ok(1.into()), casper.epoch_length());
		assert_eq!(Ok(2.into()), casper.withdrawal_delay());
		assert_eq!(Ok(3.into()), casper.dynasty_logout_delay());
		assert_eq!(Ok(7.into()), casper.base_interest_factor());
		assert_eq!(Ok(8.into()), casper.base_penalty_factor());

		assert_eq!(Ok(0.into()), casper.current_epoch());
	}
}


// QUERIES
// get_current_epoch()

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