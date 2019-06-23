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

//! Updater for Parity executables

extern crate ethabi;
extern crate ethcore;
extern crate ethcore_bytes as bytes;
extern crate ethcore_sync as sync;
extern crate ethereum_types;
extern crate keccak_hash as hash;
extern crate parity_hash_fetch as hash_fetch;
extern crate parity_version as version;
extern crate parking_lot;
extern crate path;
extern crate rand;
extern crate semver;
extern crate target_info;

#[macro_use]
extern crate ethabi_contract;
#[macro_use]
extern crate ethabi_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

#[cfg(test)]
extern crate tempdir;

#[cfg(test)]
#[macro_use]
extern crate matches;

mod service;
mod types;
mod updater;

pub use service::Service;
pub use types::{CapState, OperationsInfo, ReleaseInfo, ReleaseTrack, VersionInfo};
pub use updater::{UpdateFilter, UpdatePolicy, Updater};
