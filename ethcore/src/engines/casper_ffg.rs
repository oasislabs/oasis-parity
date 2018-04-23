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

use ethereum_types::{Address};
use machine::Call;
use super::SystemCall;

// Contract ABI from https://gist.githubusercontent.com/vbuterin/868a6213b058fb4f1fdfcf64e54f0e91/raw/33fc177da3863ec320d1ebf95816ba52ffbffbe8/casper_abi 
// via Alpha testnet instructions at https://hackmd.io/s/Hk6UiFU7z#
use_contract!(simple_casper_contract, "SimpleCasper", "res/contracts/simple_casper.json");

pub type Epoch = i128;
pub type Error = String; // TODO: [aj] should we use EngineError or more specialised error?

/// A client for the CasperFFG contract simple_casper.v.py
pub struct SimpleCasperContract {
    address: Address,
    simple_casper_contract: simple_casper_contract::SimpleCasper,
}

impl SimpleCasperContract {
    pub fn new(address: Address) -> SimpleCasperContract {
        SimpleCasperContract {
            address,
            simple_casper_contract: simple_casper_contract::SimpleCasper::default(),
        }
    }

    // pub fn current_epoch(&self, caller: &Call) -> Result<Epoch, Error> {
    //     self.simple_casper_contract.functions()
    //         .current_epoch()
    //         .call(|data|;
    // }
}

#[cfg(test)]
mod test {
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