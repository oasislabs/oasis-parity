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

//! Authority params deserialization.

use super::ValidatorSet;
use ethereum_types::Address;
use uint::Uint;

/// Authority params deserialization.
#[derive(Debug, PartialEq, Deserialize)]
pub struct AuthorityRoundParams {
	/// Block duration, in seconds.
	#[serde(rename = "stepDuration")]
	pub step_duration: Uint,
	/// Valid authorities
	pub validators: ValidatorSet,
	/// Starting step. Determined automatically if not specified.
	/// To be used for testing only.
	#[serde(rename = "startStep")]
	pub start_step: Option<Uint>,
	/// Block at which score validation should start.
	#[serde(rename = "validateScoreTransition")]
	pub validate_score_transition: Option<Uint>,
	/// Block from which monotonic steps start.
	#[serde(rename = "validateStepTransition")]
	pub validate_step_transition: Option<Uint>,
	/// Whether transitions should be immediate.
	#[serde(rename = "immediateTransitions")]
	pub immediate_transitions: Option<bool>,
	/// Reward per block in wei.
	#[serde(rename = "blockReward")]
	pub block_reward: Option<Uint>,
	/// Block at which the block reward contract should start being used.
	#[serde(rename = "blockRewardContractTransition")]
	pub block_reward_contract_transition: Option<Uint>,
	/// Block reward contract address (setting the block reward contract
	/// overrides the static block reward definition).
	#[serde(rename = "blockRewardContractAddress")]
	pub block_reward_contract_address: Option<Address>,
	/// Block at which maximum uncle count should be considered.
	#[serde(rename = "maximumUncleCountTransition")]
	pub maximum_uncle_count_transition: Option<Uint>,
	/// Maximum number of accepted uncles.
	#[serde(rename = "maximumUncleCount")]
	pub maximum_uncle_count: Option<Uint>,
	/// Block at which empty step messages should start.
	#[serde(rename = "emptyStepsTransition")]
	pub empty_steps_transition: Option<Uint>,
	/// Maximum number of accepted empty steps.
	#[serde(rename = "maximumEmptySteps")]
	pub maximum_empty_steps: Option<Uint>,
}

/// Authority engine deserialization.
#[derive(Debug, PartialEq, Deserialize)]
pub struct AuthorityRound {
	/// Ethash params.
	pub params: AuthorityRoundParams,
}

#[cfg(test)]
mod tests {
	use ethereum_types::{H160, U256};
	use hash::Address;
	use serde_json;
	use spec::authority_round::AuthorityRound;
	use spec::validator_set::ValidatorSet;
	use uint::Uint;

	#[test]
	fn authority_round_deserialization() {
		let s = r#"{
			"params": {
				"stepDuration": "0x02",
				"validators": {
					"list" : ["0xc6d9d2cd449a754c494264e1809c50e34d64562b"]
				},
				"startStep" : 24,
				"validateStepTransition": 150,
				"blockReward": 5000000,
				"maximumUncleCountTransition": 10000000,
				"maximumUncleCount": 5
			}
		}"#;

		let deserialized: AuthorityRound = serde_json::from_str(s).unwrap();
		assert_eq!(deserialized.params.step_duration, Uint(U256::from(0x02)));
		assert_eq!(
			deserialized.params.validators,
			ValidatorSet::List(vec![Address(H160::from(
				"0xc6d9d2cd449a754c494264e1809c50e34d64562b"
			))])
		);
		assert_eq!(deserialized.params.start_step, Some(Uint(U256::from(24))));
		assert_eq!(deserialized.params.immediate_transitions, None);
		assert_eq!(
			deserialized.params.maximum_uncle_count_transition,
			Some(Uint(10_000_000.into()))
		);
		assert_eq!(
			deserialized.params.maximum_uncle_count,
			Some(Uint(5.into()))
		);
	}
}
