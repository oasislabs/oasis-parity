// Copyright 2015-2017 Parity Technologies (UK) Ltd.
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

use ethereum_types::{Address};
use machine::Call;
use super::SystemCall;

use_contract!(simple_casper_contract, "SimpleCasper", "res/contracts/simple_casper.json");

pub type Epoch = i128;
pub type Error = String; // TODO: [aj] should we use EngineError or more specialised error?

/// A client for the CasperFFG contract simple_casper.v.py
pub struct SimpleCasperContract {
    address: Address,
    simple_casper_contract: simple_casper_contract::SimpleCasper,
}

impl SimpleCasperContract {
    pub fn new(address: Address) -> SimpleCasperContract {
        SimpleCasperContract {
            address,
            simple_casper_contract: simple_casper_contract::SimpleCasper::default(),
        }
    }

    pub fn current_epoch(&self, caller: &Call) -> Result<Epoch, Error> {
        self.simple_casper_contract.functions()
            .current_epoch()
            .call(|data|;
    }
}

// QUERIES
// get_current_epoch()

// VALIDATOR COMMANDS
// initialize_epoch
// https://github.com/ethereum/casper/blob/master/casper/contracts/simple_casper.v.py#L248

// deposit 
// https://github.com/ethereum/casper/blob/master/casper/contracts/simple_casper.v.py#L281

// logout
// https://github.com/ethereum/casper/blob/master/casper/contracts/simple_casper.v.py#L302

// withdraw
// https://github.com/ethereum/casper/blob/master/casper/contracts/simple_casper.v.py#L338

// vote
// https://github.com/ethereum/casper/blob/master/casper/contracts/simple_casper.v.py#L370

// slash
// https://github.com/ethereum/casper/blob/master/casper/contracts/simple_casper.v.py#L443