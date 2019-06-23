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

//! Ethcore rpc v1.
//!
//! Compliant with ethereum rpc.

// short for "try_boxfuture"
// unwrap a result, returning a BoxFuture<_, Err> on failure.
macro_rules! try_bf {
	($res: expr) => {
		match $res {
			Ok(val) => val,
			Err(e) => return Box::new(::jsonrpc_core::futures::future::err(e.into())),
			}
	};
}

#[macro_use]
pub mod helpers;
//mod impls;
#[cfg(test)]
mod tests;
pub mod types;

pub mod extractors;
pub mod informant;
pub mod metadata;
pub mod traits;

pub use self::traits::{
	Eth, EthFilter, EthPubSub, EthSigning, Net, ParitySigning, Personal, Private, PubSub, Rpc,
	SecretStore, Signer, Web3,
};
//pub use self::impls::*;
pub use self::extractors::{RpcExtractor, WsDispatcher, WsExtractor, WsStats};
pub use self::helpers::NetworkSettings;
pub use self::metadata::Metadata;
pub use self::types::Origin;

/// Signer utilities
/*
pub mod signer {
	pub use super::helpers::{SigningQueue, SignerService, ConfirmationsQueue};
	pub use super::types::{ConfirmationRequest, TransactionModification, U256, TransactionCondition};
}
*/

/// Dapps integration utilities
pub mod dapps {
	pub use super::helpers::dapps::DappsService;
	pub use super::types::LocalDapp;
}
