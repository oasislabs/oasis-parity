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
use_contract!(simple_casper_contract, "SimpleCasper", "res/contracts/simple_casper.json");

pub type Epoch = U256;
pub type Error = String; // TODO: [aj] should we use EngineError or more specialised error?

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
	// }

    pub fn current_epoch(&self) -> Result<Epoch, Error> {
        self.simple_casper_contract.functions()
            .current_epoch()
            .call(&|data| {
				println!("Data: {:?}", data);
				self.client.call_contract(BlockId::Latest, self.address, data)
			})
			.map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod test {
	use super::{SimpleCasperContract};
	use ethabi::{encode, Token};
	use ethereum_types::U256;
	use client::{BlockId, CallContract};
	use spec::Spec;
	use rustc_hex::ToHex;
	use test_helpers::generate_dummy_client_with_spec_and_accounts;

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
		let owner = Token::Address("0000000000000000000000000000000000000010".into());
		let sighasher = Token::Address("0000000000000000000000000000000000000020".into());
		let purity_checker = Token::Address("0000000000000000000000000000000000000030".into());
		let base_interest_factor = Token::Int(4u32.into()); // int instead of decimal
		let base_penalty_factor = Token::Int(5u32.into()); // todo: convert decimal value to int equivalent

		let encoded = encode(&[epoch_length, withdrawal_delay, dynasty_logout_delay, owner, sighasher, purity_checker, base_interest_factor, base_penalty_factor]);
		println!("ENCODED: '{:?}'", encoded.to_hex());

		// result: pasted after 36000f3 in casper_ffg.json
		// 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000005
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

		// let's see what int128 looks like
		let data = vec![147u8, 114u8, 180u8, 228u8];
		println!("data: {:?}", data);
		let x = client.call_contract(BlockId::Latest, casper.address, data);
		println!("Call contract result {:?}", x);

		assert_eq!(Ok(0.into()), casper.current_epoch());
	}
    // create contract constructor with bytecode + abi encoded constructor parms
    // instantiate contract
    // use client to read public properties!

	// use client::PrepareOpenBlock;
	// use ethereum_types::U256;
	// use spec::Spec;
	// use test_helpers::generate_dummy_client_with_spec_and_accounts;

	// use super::{BlockRewardContract, RewardKind};

	// #[test]
	// fn block_reward_contract() {
	// 	let client = generate_dummy_client_with_spec_and_accounts(
	// 		Spec::new_test_round_block_reward_contract,
	// 		None,
	// 	);

	// 	let machine = Spec::new_test_machine();

	// 	// the spec has a block reward contract defined at the given address
	// 	let block_reward_contract = BlockRewardContract::new(
	// 		"0000000000000000000000000000000000000042".into(),
	// 	);

	// 	let mut call = |to, data| {
	// 		let mut block = client.prepare_open_block(
	// 			"0000000000000000000000000000000000000001".into(),
	// 			(3141562.into(), 31415620.into()),
	// 			vec![],
	// 		);

	// 		let result = machine.execute_as_system(
	// 			block.block_mut(),
	// 			to,
	// 			U256::max_value(),
	// 			Some(data),
	// 		);

	// 		result.map_err(|e| format!("{}", e))
	// 	};

	// 	// if no benefactors are given no rewards are attributed
	// 	assert!(block_reward_contract.reward(&vec![], &mut call).unwrap().is_empty());

	// 	// the contract rewards (1000 + kind) for each benefactor
	// 	let benefactors = vec![
	// 		("0000000000000000000000000000000000000033".into(), RewardKind::Author),
	// 		("0000000000000000000000000000000000000034".into(), RewardKind::Uncle),
	// 		("0000000000000000000000000000000000000035".into(), RewardKind::EmptyStep),
	// 	];

	// 	let rewards = block_reward_contract.reward(&benefactors, &mut call).unwrap();
	// 	let expected = vec![
	// 		("0000000000000000000000000000000000000033".into(), U256::from(1000)),
	// 		("0000000000000000000000000000000000000034".into(), U256::from(1000 + 1)),
	// 		("0000000000000000000000000000000000000035".into(), U256::from(1000 + 2)),
	// 	];

	// 	assert_eq!(expected, rewards);
	// }
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