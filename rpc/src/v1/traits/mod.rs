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

//! Ethereum rpc interfaces.

pub mod eth;
pub mod eth_pubsub;
pub mod eth_signing;
pub mod net;
pub mod web3;
//pub mod parity;
//pub mod parity_accounts;
//pub mod parity_set;
pub mod parity_signing;
pub mod personal;
pub mod pubsub;
pub mod signer;
//pub mod traces;
pub mod private;
pub mod rpc;
pub mod secretstore;

pub use self::eth::{Eth, EthFilter};
pub use self::eth_pubsub::EthPubSub;
pub use self::eth_signing::EthSigning;
pub use self::net::Net;
pub use self::web3::Web3;
//pub use self::parity::Parity;
//pub use self::parity_accounts::ParityAccounts;
//pub use self::parity_set::ParitySet;
pub use self::parity_signing::ParitySigning;
pub use self::personal::Personal;
pub use self::pubsub::PubSub;
pub use self::signer::Signer;
//pub use self::traces::Traces;
pub use self::private::Private;
pub use self::rpc::Rpc;
pub use self::secretstore::SecretStore;
