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

use ethcore::filter::Filter as EthFilter;
use ethcore::filter::TxFilter as EthTxFilter;
use ethcore::ids::BlockId;
use ethereum_types::Address;
use serde::de::{DeserializeOwned, Error};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{from_value, Value};
use v1::types::{BlockNumber, Log, H160, H256};

/// Variadic value
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum VariadicValue<T>
where
	T: DeserializeOwned,
{
	/// Single
	Single(T),
	/// List
	Multiple(Vec<T>),
	/// None
	Null,
}

impl<'a, T> Deserialize<'a> for VariadicValue<T>
where
	T: DeserializeOwned,
{
	fn deserialize<D>(deserializer: D) -> Result<VariadicValue<T>, D::Error>
	where
		D: Deserializer<'a>,
	{
		let v: Value = Deserialize::deserialize(deserializer)?;

		if v.is_null() {
			return Ok(VariadicValue::Null);
		}

		from_value(v.clone())
			.map(VariadicValue::Single)
			.or_else(|_| from_value(v).map(VariadicValue::Multiple))
			.map_err(|err| D::Error::custom(format!("Invalid variadic value type: {}", err)))
	}
}

/// Filter Address
pub type FilterAddress = VariadicValue<H160>;
/// Topic
pub type Topic = VariadicValue<H256>;

/// Filter
#[derive(Debug, PartialEq, Clone, Deserialize, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct Filter {
	/// From Block
	#[serde(rename = "fromBlock")]
	pub from_block: Option<BlockNumber>,
	/// To Block
	#[serde(rename = "toBlock")]
	pub to_block: Option<BlockNumber>,
	/// Address
	pub address: Option<FilterAddress>,
	/// Topics
	pub topics: Option<Vec<Topic>>,
	/// Limit
	pub limit: Option<usize>,
}

impl Into<EthFilter> for Filter {
	fn into(self) -> EthFilter {
		let num_to_id = |num| match num {
			BlockNumber::Num(n) => BlockId::Number(n),
			BlockNumber::Earliest => BlockId::Earliest,
			BlockNumber::Latest | BlockNumber::Pending => BlockId::Latest,
		};

		EthFilter {
			from_block: self.from_block.map_or_else(|| BlockId::Latest, &num_to_id),
			to_block: self.to_block.map_or_else(|| BlockId::Latest, &num_to_id),
			address: self.address.and_then(|address| match address {
				VariadicValue::Null => None,
				VariadicValue::Single(a) => Some(vec![a.into()]),
				VariadicValue::Multiple(a) => Some(a.into_iter().map(Into::into).collect()),
			}),
			topics: {
				let mut iter = self
					.topics
					.map_or_else(Vec::new, |topics| {
						topics
							.into_iter()
							.take(4)
							.map(|topic| match topic {
								VariadicValue::Null => None,
								VariadicValue::Single(t) => Some(vec![t.into()]),
								VariadicValue::Multiple(t) => {
									Some(t.into_iter().map(Into::into).collect())
								}
							})
							.collect()
					})
					.into_iter();

				vec![
					iter.next().unwrap_or(None),
					iter.next().unwrap_or(None),
					iter.next().unwrap_or(None),
					iter.next().unwrap_or(None),
				]
			},
			limit: self.limit,
		}
	}
}

/// Results of the filter_changes RPC.
#[derive(Debug, PartialEq)]
pub enum FilterChanges {
	/// New logs.
	Logs(Vec<Log>),
	/// New hashes (block or transactions)
	Hashes(Vec<H256>),
	/// Empty result,
	Empty,
}

/// TxFilter is a filter for transactions
#[derive(Debug, PartialEq, Clone, Deserialize, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct TxFilter {
	/// Transaction hash.
	#[serde(rename = "transactionHash")]
	pub transaction_hash: Option<H256>,

	/// From address
	#[serde(rename = "fromAddress")]
	pub from_address: Option<Address>,
}

impl Into<EthTxFilter> for TxFilter {
	fn into(self) -> EthTxFilter {
		EthTxFilter {
			transaction_hash: match self.transaction_hash {
				Some(hash) => Some(hash.into()),
				None => None,
			},
			from_address: match self.from_address {
				Some(from_address) => Some(from_address),
				None => None,
			},
		}
	}
}

impl Serialize for FilterChanges {
	fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match *self {
			FilterChanges::Logs(ref logs) => logs.serialize(s),
			FilterChanges::Hashes(ref hashes) => hashes.serialize(s),
			FilterChanges::Empty => (&[] as &[Value]).serialize(s),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::{Filter, Topic, VariadicValue};
	use ethcore::client::BlockId;
	use ethcore::filter::Filter as EthFilter;
	use ethereum_types::H256;
	use serde_json;
	use std::str::FromStr;
	use v1::types::BlockNumber;

	#[test]
	fn topic_deserialization() {
		let s = r#"["0x000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b", null, ["0x000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b", "0x0000000000000000000000000aff3454fce5edbc8cca8697c15331677e6ebccc"]]"#;
		let deserialized: Vec<Topic> = serde_json::from_str(s).unwrap();
		assert_eq!(
			deserialized,
			vec![
				VariadicValue::Single(
					H256::from_str(
						"000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b"
					)
					.unwrap()
					.into()
				),
				VariadicValue::Null,
				VariadicValue::Multiple(vec![
					H256::from_str(
						"000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b"
					)
					.unwrap()
					.into(),
					H256::from_str(
						"0000000000000000000000000aff3454fce5edbc8cca8697c15331677e6ebccc"
					)
					.unwrap()
					.into(),
				])
			]
		);
	}

	#[test]
	fn filter_deserialization() {
		let s = r#"{"fromBlock":"earliest","toBlock":"latest"}"#;
		let deserialized: Filter = serde_json::from_str(s).unwrap();
		assert_eq!(
			deserialized,
			Filter {
				from_block: Some(BlockNumber::Earliest),
				to_block: Some(BlockNumber::Latest),
				address: None,
				topics: None,
				limit: None,
			}
		);
	}

	#[test]
	fn filter_conversion() {
		let filter = Filter {
			from_block: Some(BlockNumber::Earliest),
			to_block: Some(BlockNumber::Latest),
			address: Some(VariadicValue::Multiple(vec![])),
			topics: Some(vec![
				VariadicValue::Null,
				VariadicValue::Single(
					"000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b".into(),
				),
				VariadicValue::Null,
			]),
			limit: None,
		};

		let eth_filter: EthFilter = filter.into();
		assert_eq!(
			eth_filter,
			EthFilter {
				from_block: BlockId::Earliest,
				to_block: BlockId::Latest,
				address: Some(vec![]),
				topics: vec![
					None,
					Some(vec![
						"000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b".into()
					]),
					None,
					None,
				],
				limit: None,
			}
		);
	}

	#[test]
	fn tx_filter_deserialization() {
		let s = r#"{"transactionHash":"0x000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b"}"#;
		let deserialized: TxFilter = serde_json::from_str(s).unwrap();
		assert_eq!(
			deserialized,
			TxFilter {
				transaction_hash:
					"0x000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b",
			}
		);
	}

	#[test]
	fn filter_conversion() {
		let filter = TxFilter {
			transactionHash: "0x000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b",
		};

		let eth_filter: EthTxFilter = filter.into();

		assert_eq!(
			eth_filter,
			EthTxFilter {
				transactionHash:
					"0x000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b"
			}
		);
	}
}
