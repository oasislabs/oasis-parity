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

use ethabi::{Address, Bytes};
use futures::{future, Future, IntoFuture};
use keccak_hash::keccak;
use std::sync::Arc;

use_contract!(registry, "Registry", "res/registrar.json");

// Maps a domain name to an Ethereum address
const DNS_A_RECORD: &'static str = "A";

pub type Asynchronous = Box<Future<Item = Bytes, Error = String> + Send>;
pub type Synchronous = Result<Bytes, String>;

/// Registrar is dedicated interface to access the registrar contract
/// which in turn generates an address when a client requests one
pub struct Registrar {
	registrar: registry::Registry,
	client: Arc<RegistrarClient<Call = Asynchronous>>,
}

impl Registrar {
	/// Registrar constructor
	pub fn new(client: Arc<RegistrarClient<Call = Asynchronous>>) -> Self {
		Self {
			registrar: registry::Registry::default(),
			client: client,
		}
	}

	/// Generate an address for the given key
	pub fn get_address<'a>(
		&self,
		key: &'a str,
	) -> Box<Future<Item = Address, Error = String> + Send> {
		// Address of the registrar itself
		let registrar_address = match self.client.registrar_address() {
			Ok(a) => a,
			Err(e) => return Box::new(future::err(e)),
		};

		let address_fetcher = self.registrar.functions().get_address();
		let id = address_fetcher.input(keccak(key), DNS_A_RECORD);

		let future = self
			.client
			.call_contract(registrar_address, id)
			.and_then(move |address| {
				{ address_fetcher.output(&address) }.map_err(|e| e.to_string())
			});

		Box::new(future)
	}
}

/// Registrar contract interface
/// Should execute transaction using current blockchain state.
pub trait RegistrarClient: Send + Sync {
	/// Specifies synchronous or asynchronous communication
	type Call: IntoFuture<Item = Bytes, Error = String>;

	/// Get registrar address
	fn registrar_address(&self) -> Result<Address, String>;
	/// Call Contract
	fn call_contract(&self, address: Address, data: Bytes) -> Self::Call;
}
