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

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use dir::default_data_path;
use dir::helpers::replace_home;
use ethcore::client::{BlockChainClient, BlockId, CallContract, Client};
use ethereum_types::Address;
use futures::{future, Future, IntoFuture};
use futures_cpupool::CpuPool;
use hash_fetch::fetch::Client as FetchClient;
use light::client::LightChainClient;
use light::on_demand::{self, OnDemand};
use node_health::{NodeHealth, SyncStatus};
use registrar::{Asynchronous, RegistrarClient};
use rpc;
use rpc_apis::SignerService;
use sync::LightSync;
use transaction::{Action, Transaction};

#[derive(Debug, PartialEq, Clone)]
pub struct Configuration {
	pub enabled: bool,
	pub dapps_path: PathBuf,
	pub extra_dapps: Vec<PathBuf>,
}

impl Default for Configuration {
	fn default() -> Self {
		let data_dir = default_data_path();
		Configuration {
			enabled: true,
			dapps_path: replace_home(&data_dir, "$BASE/dapps").into(),
			extra_dapps: vec![],
		}
	}
}

impl Configuration {
	pub fn address(&self, address: Option<::parity_rpc::Host>) -> Option<::parity_rpc::Host> {
		match self.enabled {
			true => address,
			false => None,
		}
	}
}

/// Registrar implementation of the full client.
pub struct FullRegistrar {
	/// Handle to the full client.
	pub client: Arc<Client>,
}

impl FullRegistrar {
	pub fn new(client: Arc<Client>) -> Self {
		FullRegistrar { client }
	}
}

impl RegistrarClient for FullRegistrar {
	type Call = Asynchronous;

	fn registrar_address(&self) -> Result<Address, String> {
		self.client
			.registrar_address()
			.ok_or_else(|| "Registrar not defined.".into())
	}

	fn call_contract(&self, address: Address, data: Bytes) -> Self::Call {
		Box::new(
			self.client
				.call_contract(BlockId::Latest, address, data)
				.into_future(),
		)
	}
}

/// Registrar implementation for the light client.
pub struct LightRegistrar<T> {
	/// The light client.
	pub client: Arc<T>,
	/// Handle to the on-demand service.
	pub on_demand: Arc<OnDemand>,
	/// Handle to the light network service.
	pub sync: Arc<LightSync>,
}

impl<T: LightChainClient + 'static> RegistrarClient for LightRegistrar<T> {
	type Call = Box<Future<Item = Bytes, Error = String> + Send>;

	fn registrar_address(&self) -> Result<Address, String> {
		self.client
			.engine()
			.additional_params()
			.get("registrar")
			.ok_or_else(|| "Registrar not defined.".into())
			.and_then(|registrar| {
				registrar
					.parse()
					.map_err(|e| format!("Invalid registrar address: {:?}", e))
			})
	}

	fn call_contract(&self, address: Address, data: Bytes) -> Self::Call {
		let header = self.client.best_block_header();
		let env_info = self
			.client
			.env_info(BlockId::Hash(header.hash()))
			.ok_or_else(|| format!("Cannot fetch env info for header {}", header.hash()));

		let env_info = match env_info {
			Ok(e) => e,
			Err(e) => return Box::new(future::err(e)),
		};

		let maybe_future = self.sync.with_context(move |ctx| {
			self.on_demand
				.request(
					ctx,
					on_demand::request::TransactionProof {
						tx: Transaction {
							nonce: self.client.engine().account_start_nonce(header.number()),
							action: Action::Call(address),
							gas: 50_000.into(), // should be enough for all registry lookups. TODO: exponential backoff
							gas_price: 0.into(),
							value: 0.into(),
							data: data,
						}
						.fake_sign(Address::default()),
						header: header.into(),
						env_info: env_info,
						engine: self.client.engine().clone(),
					},
				)
				.expect("No back-references; therefore all back-refs valid; qed")
				.then(|res| match res {
					Ok(Ok(executed)) => Ok(executed.output),
					Ok(Err(e)) => Err(format!("Failed to execute transaction: {}", e)),
					Err(_) => Err(format!("On-demand service dropped request unexpectedly.")),
				})
		});

		match maybe_future {
			Some(fut) => Box::new(fut),
			None => Box::new(future::err(
				"cannot query registry: network disabled".into(),
			)),
		}
	}
}

// TODO: light client implementation forwarding to OnDemand and waiting for future
// to resolve.
#[derive(Clone)]
pub struct Dependencies {
	pub node_health: NodeHealth,
	pub sync_status: Arc<SyncStatus>,
	pub contract_client: Arc<RegistrarClient<Call = Asynchronous>>,
	pub fetch: FetchClient,
	pub pool: CpuPool,
	pub signer: Arc<SignerService>,
}

pub fn new(configuration: Configuration, deps: Dependencies) -> Result<Option<Middleware>, String> {
	if !configuration.enabled {
		return Ok(None);
	}

	server::dapps_middleware(
		deps,
		configuration.dapps_path,
		configuration.extra_dapps,
		rpc::DAPPS_DOMAIN,
	)
	.map(Some)
}

pub use self::server::{service, Middleware};

#[cfg(not(feature = "dapps"))]
mod server {
	use super::Dependencies;
	use parity_rpc::{hyper, RequestMiddleware, RequestMiddlewareAction};
	use rpc_apis;
	use std::path::PathBuf;
	use std::sync::Arc;

	pub struct Middleware;
	impl RequestMiddleware for Middleware {
		fn on_request(&self, _req: hyper::Request) -> RequestMiddlewareAction {
			unreachable!()
		}
	}

	pub fn dapps_middleware(
		_deps: Dependencies,
		_dapps_path: PathBuf,
		_extra_dapps: Vec<PathBuf>,
		_dapps_domain: &str,
	) -> Result<Middleware, String> {
		Err("Your Parity version has been compiled without WebApps support.".into())
	}

	pub fn service(_: &Option<Middleware>) -> Option<Arc<rpc_apis::DappsService>> {
		None
	}
}

#[cfg(feature = "dapps")]
mod server {
	use super::Dependencies;
	use rpc_apis;
	use std::path::PathBuf;
	use std::sync::Arc;

	use parity_dapps;

	pub use parity_dapps::Middleware;

	pub fn dapps_middleware(
		deps: Dependencies,
		dapps_path: PathBuf,
		extra_dapps: Vec<PathBuf>,
		dapps_domain: &str,
	) -> Result<Middleware, String> {
		let signer = deps.signer;
		let web_proxy_tokens = Arc::new(move |token| signer.web_proxy_access_token_domain(&token));

		Ok(parity_dapps::Middleware::dapps(
			deps.pool,
			deps.node_health,
			dapps_path,
			extra_dapps,
			dapps_domain,
			deps.contract_client,
			deps.sync_status,
			web_proxy_tokens,
			deps.fetch,
		))
	}

	pub fn service(middleware: &Option<Middleware>) -> Option<Arc<rpc_apis::DappsService>> {
		middleware.as_ref().map(|m| {
			Arc::new(DappsServiceWrapper {
				endpoints: m.endpoints().clone(),
			}) as Arc<rpc_apis::DappsService>
		})
	}

	pub struct DappsServiceWrapper {
		endpoints: parity_dapps::Endpoints,
	}

	impl rpc_apis::DappsService for DappsServiceWrapper {
		fn list_dapps(&self) -> Vec<rpc_apis::LocalDapp> {
			self.endpoints
				.list()
				.into_iter()
				.map(|app| rpc_apis::LocalDapp {
					id: app.id.unwrap_or_else(|| "unknown".into()),
					name: app.name,
					description: app.description,
					version: app.version,
					author: app.author,
					icon_url: app.icon_url,
					local_url: app.local_url,
				})
				.collect()
		}

		fn refresh_local_dapps(&self) -> bool {
			self.endpoints.refresh_local_dapps();
			true
		}
	}
}
