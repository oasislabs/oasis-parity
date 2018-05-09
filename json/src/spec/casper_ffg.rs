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

//! Authority params deserialization.

use ethereum_types::Address;
use uint::Uint;

#[derive(Debug, PartialEq, Deserialize)]
pub struct CasperContractParams {
    // EPOCH_LENGTH: 50 blocks
    #[serde(rename="epochLength")]
    pub epoch_length: Option<Uint>,
    // WITHDRAWAL_DELAY: 15,000 epochs
    #[serde(rename="withdrawalDelay")]
    pub withdrawal_delay: Option<Uint>,
    // DYNASTY_LOGOUT_DELAY: 700 dynasties
    #[serde(rename="dynastyLogoutDelay")]
    pub dynasty_logout_delay: Option<Uint>,
    // BASE_INTEREST_FACTOR: 7e-3
    #[serde(rename="baseInterestFactor")]
    pub base_interest_factor: Option<f32>,
    // BASE_PENALTY_FACTOR: 2e-7
    #[serde(rename="basePenaltyFactor")]
    pub base_penalty_factor: Option<f32>,
    // MIN_DEPOSIT_SIZE: 1.5e21 wei (1500 ETH)
    #[serde(rename="minDepositSizeEth")]
    pub min_deposit_size_eth: Option<Uint>,
}

/// Casper FFG params deserialisation
#[derive(Debug, PartialEq, Deserialize)]
pub struct CasperFfgParams {

    #[serde(rename="contract_params")]
    pub contract_params: Option<CasperContractParams>,

    // HYBRID_CASPER_FORK_BLKNUM: TBD
    #[serde(rename="hybridCasperForkBlockNumber")]
    pub hybrid_casper_fork_block_number: Option<Uint>,

    // CASPER_BALANCE: 1e24 wei (1,000,000 ETH)
    // SIGHASHER_ADDR: TBD
    // SIGHASHER_CODE: see below
    // PURITY_CHECKER_ADDR: TBD
    // PURITY_CHECKER_CODE: see below
    // NULL_SENDER: 2**160 - 1
    // NEW_BLOCK_REWARD: 6e17 wei (0.6 ETH)
    // NON_REVERT_MIN_DEPOSIT: amount in wei configurable by client

    
}

/// Authority engine deserialization.
#[derive(Debug, PartialEq, Deserialize)]
pub struct CasperFfg {
	/// CasperFFG params.
	pub params: CasperFfgParams,
}

#[cfg(test)]
mod tests {
	use ethereum_types::{U256, H160};
	use uint::Uint;
	use serde_json;
	use hash::Address;
	use spec::validator_set::ValidatorSet;
	use spec::authority_round::AuthorityRound;

	#[test]
	fn casper_params_deserialisation() {
		let s = r#"{
			"params": {
                "contractParams": {
                    epochLength: 50,
                    withdrawalDelay: 15000,
                    dynastyLogoutDelay: 700,
                    baseInterestFactor: 7e-3,
                    basePenaltyFactor: 2e-7,
                    minDepositSizeEth: 1500,
                },
				"hybridCasperForkBlknum": 100,
			}
		}"#;

		let deserialized: CasperFfg = serde_json::from_str(s).unwrap();
        let contract_params = deserialized.params.contract_params.unwrap();
		assert_eq!(deserialized.params.hybrid_casper_fork_block_number, Some(100));
        assert_eq!(params.epoch_length, Some(15000));
		// assert_eq!(deserialized.params.validators, ValidatorSet::List(vec![Address(H160::from("0xc6d9d2cd449a754c494264e1809c50e34d64562b"))]));
		// assert_eq!(deserialized.params.start_step, Some(Uint(U256::from(24))));
		// assert_eq!(deserialized.params.immediate_transitions, None);
		// assert_eq!(deserialized.params.maximum_uncle_count_transition, Some(Uint(10_000_000.into())));
		// assert_eq!(deserialized.params.maximum_uncle_count, Some(Uint(5.into())));

	}
}
