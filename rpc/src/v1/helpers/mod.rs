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

#[macro_use]
pub mod errors;

pub mod dapps;
pub mod fake_sign;
pub mod ipfs;
pub mod nonce;
pub mod oneshot;

mod network_settings;
mod poll_filter;
mod poll_manager;
mod requests;
mod subscribers;
mod subscription_manager;

pub use self::network_settings::NetworkSettings;
pub use self::poll_filter::{limit_logs, PollFilter};
pub use self::poll_manager::PollManager;
pub use self::requests::{
	CallRequest, ConfirmationPayload, ConfirmationRequest, FilledTransactionRequest,
	TransactionRequest,
};
pub use self::subscribers::Subscribers;
pub use self::subscription_manager::GenericPollManager;

pub fn to_url(address: &Option<::Host>) -> Option<String> {
	address.as_ref().map(|host| (**host).to_owned())
}
