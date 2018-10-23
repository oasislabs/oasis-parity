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

use engines::{Engine, Seal};
use parity_machine::{Machine, Transactions, TotalScoredHeader};

/// An engine which does not provide any consensus mechanism, just seals blocks internally.
/// Only seals blocks which have transactions.
pub struct InstantSeal<M> {
	machine: M,
}

impl<M> InstantSeal<M> {
	/// Returns new instance of InstantSeal over the given state machine.
	pub fn new(machine: M) -> Self {
		InstantSeal {
			machine: machine,
		}
	}
}

impl<M: Machine> Engine<M> for InstantSeal<M>
  where M::LiveBlock: Transactions,
        M::ExtendedHeader: TotalScoredHeader,
        <M::ExtendedHeader as TotalScoredHeader>::Value: Ord
{
	fn name(&self) -> &str {
		"InstantSeal"
	}

	fn machine(&self) -> &M { &self.machine }

	fn seals_internally(&self) -> Option<bool> { Some(true) }

	fn generate_seal(&self, block: &M::LiveBlock, _parent: &M::Header) -> Seal {
		if block.transactions().is_empty() { Seal::None } else { Seal::Regular(Vec::new()) }
	}

	fn verify_local_seal(&self, _header: &M::Header) -> Result<(), M::Error> {
		Ok(())
	}

	fn open_block_header_timestamp(&self, parent_timestamp: u64) -> u64 {
		use std::{time, cmp};

		let now = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap_or_default();
		cmp::max(now.as_secs(), parent_timestamp)
	}

	fn is_timestamp_valid(&self, header_timestamp: u64, parent_timestamp: u64) -> bool {
		header_timestamp >= parent_timestamp
	}

	fn fork_choice(&self, new: &M::ExtendedHeader, current: &M::ExtendedHeader) -> super::ForkChoice {
		super::total_difficulty_fork_choice(new, current)
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;
	use ethereum_types::{H520, Address};
	use test_helpers::get_temp_state_db;
	use spec::Spec;
	use header::Header;
	use block::*;
	use engines::Seal;

	#[test]
	fn instant_can_seal() {
		let spec = Spec::new_instant();
		let engine = &*spec.engine;
		let db = spec.ensure_db_good(get_temp_state_db(), &Default::default()).unwrap();
		let genesis_header = spec.genesis_header();
		let last_hashes = Arc::new(vec![genesis_header.hash()]);
		let b = OpenBlock::new(engine, Default::default(), false, db, &genesis_header, last_hashes, Address::default(), 31415620.into(), vec![], false, &mut Vec::new().into_iter(), None, None).unwrap();
		let b = b.close_and_lock();
		if let Seal::Regular(seal) = engine.generate_seal(b.block(), &genesis_header) {
			assert!(b.try_seal(engine, seal).is_ok());
		}
	}

	#[test]
	fn instant_cant_verify() {
		let engine = Spec::new_instant().engine;
		let mut header: Header = Header::default();

		assert!(engine.verify_block_basic(&header).is_ok());

		header.set_seal(vec![::rlp::encode(&H520::default()).into_vec()]);

		assert!(engine.verify_block_unordered(&header).is_ok());
	}
}
