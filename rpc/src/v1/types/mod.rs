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

//! RPC types

mod account_info;
mod block;
mod block_number;
mod bytes;
mod call_request;
mod confirmations;
mod dapps;
mod filter;
mod hash;
mod histogram;
mod index;
mod log;
mod node_kind;
mod private_receipt;
mod provenance;
mod receipt;
mod rpc_settings;
mod secretstore;
mod transaction;
mod transaction_condition;
mod transaction_outcome;
mod transaction_request;
mod uint;
mod work;

pub mod pubsub;

pub use self::account_info::{AccountInfo, ExtAccountInfo, HwAccountInfo};
pub use self::block::{Block, BlockTransactions, Header, Rich, RichBlock, RichHeader};
pub use self::block_number::{block_number_to_id, BlockNumber};
pub use self::bytes::Bytes;
pub use self::call_request::CallRequest;
pub use self::confirmations::{
	ConfirmationPayload, ConfirmationRequest, ConfirmationResponse, ConfirmationResponseWithToken,
	DecryptRequest, Either, SignRequest, TransactionModification,
};
pub use self::dapps::LocalDapp;
pub use self::filter::{Filter, FilterChanges, TxFilter};
pub use self::hash::{H160, H2048, H256, H512, H520, H64};
pub use self::histogram::Histogram;
pub use self::index::Index;
pub use self::log::Log;
pub use self::node_kind::{Availability, Capability, NodeKind};
pub use self::private_receipt::{
	PrivateTransactionReceipt, PrivateTransactionReceiptAndTransaction,
};
pub use self::provenance::{DappId, Origin};
pub use self::receipt::Receipt;
pub use self::rpc_settings::RpcSettings;
pub use self::secretstore::EncryptedDocumentKey;
pub use self::transaction::{LocalTransactionStatus, RichRawTransaction, Transaction};
pub use self::transaction_condition::TransactionCondition;
pub use self::transaction_outcome::TransactionOutcome;
pub use self::transaction_request::TransactionRequest;
pub use self::uint::{U128, U256, U64};
pub use self::work::Work;

// TODO [ToDr] Refactor to a proper type Vec of enums?
/// Expected tracing type.
pub type TraceOptions = Vec<String>;
