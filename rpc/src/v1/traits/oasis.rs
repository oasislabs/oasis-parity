//! Eth rpc interface.
use jsonrpc_core::{Result, BoxFuture};
use jsonrpc_macros::Trailing;

use v1::types::{H256, U256, Bytes};

build_rpc_trait! {
	pub trait Oasis {
		/// Request data from storage.
		#[rpc(name = "oasis_requestBytes")]
		fn request_bytes(&self, H256, U256, U256) -> Result<Bytes>;

		/// Store data in global storage.
		#[rpc(name = "oasis_storeBytes")]
		fn store_bytes(&self, Bytes, U256) -> Result<H256>;
	}
}
