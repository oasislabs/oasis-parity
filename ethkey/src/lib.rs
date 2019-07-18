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

// #![warn(missing_docs)]

extern crate byteorder;
extern crate edit_distance;
extern crate ethereum_types;
extern crate mem;
#[macro_use]
extern crate quick_error;
#[cfg(any(test, feature = "test"))]
extern crate rand;
extern crate rustc_hex;
extern crate secp256k1;
extern crate tiny_keccak;

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

mod error;
mod keccak;
mod keypair;
#[cfg(any(test, feature = "test"))]
mod random;
mod secret;
mod signature;

pub use self::error::Error;
pub use self::keypair::{public_to_address, KeyPair};
#[cfg(any(test, feature = "test"))]
pub use self::random::Random;
pub use self::secret::Secret;
pub use self::signature::{recover, sign, verify_address, verify_public, Signature};

use ethereum_types::H256;

pub use ethereum_types::{Address, Public};
pub type Message = H256;

lazy_static! {
	pub static ref SECP256K1: secp256k1::Secp256k1 = secp256k1::Secp256k1::new();
}

/// Uninstantiatable error type for infallible generators.
#[cfg(any(test, feature = "test"))]
#[derive(Debug)]
pub enum Void {}

/// Generates new keypair.
#[cfg(any(test, feature = "test"))]
pub trait Generator {
	type Error;

	/// Should be called to generate new keypair.
	fn generate(&mut self) -> Result<KeyPair, Self::Error>;
}
