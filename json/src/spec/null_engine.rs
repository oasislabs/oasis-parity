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

//! Null engine params deserialization.

use uint::Uint;

/// Authority params deserialization.
#[derive(Debug, PartialEq, Deserialize)]
pub struct NullEngineParams {
	/// Block reward.
	#[serde(rename = "blockReward")]
	pub block_reward: Option<Uint>,
}

/// Null engine descriptor
#[derive(Debug, PartialEq, Deserialize)]
pub struct NullEngine {
	/// Ethash params.
	pub params: NullEngineParams,
}

#[cfg(test)]
mod tests {
	use super::*;
	use ethereum_types::U256;
	use serde_json;
	use uint::Uint;

	#[test]
	fn null_engine_deserialization() {
		let s = r#"{
			"params": {
				"blockReward": "0x0d"
			}
		}"#;

		let deserialized: NullEngine = serde_json::from_str(s).unwrap();
		assert_eq!(
			deserialized.params.block_reward,
			Some(Uint(U256::from(0x0d)))
		);
	}
}
