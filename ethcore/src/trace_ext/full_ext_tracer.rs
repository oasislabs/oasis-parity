// Copyright 2018 Oasis Labs.
// This file is part of Parity.
//
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

use std::convert::Into;
use std::fmt; // debug use: Display trait
use std::sync::{Arc, Mutex};
use std::vec;

use ethereum_types::{Address, H256};

use trace_ext::ext_tracer::ExtTracer;

// Internal representation -- the trace in Call requires mutex locks, because the trace is
// shared with the subtracer; we could pass ownership of the subtrace's log in the subtrace's
// drop method, but that's even messier/trickier.
struct SubTrace {
	contract: Address,
	trace: Arc<Mutex<Vec<Internal>>>,
}

enum Internal {
	Read(H256),
	Write(H256),
	Exists(Address),
	ExistsNotNull(Address),
	Balance(Address),
	Call(SubTrace),
}

/// Full logging externalities tracer.  Opaque internal trace data representation.  The drain()
/// method takes ownership of / destroys the object while returning the external representation
/// of the trace data.
pub struct FullExtTracer {
	inner: SubTrace,
}

impl SubTrace {
	fn new(contract: &Address) -> Self {
		let empty_vec: Vec<Internal> = vec![];
		Self {
			contract: *contract,
			trace: Arc::new(Mutex::new(empty_vec)),
		}
	}

	// shallow_clone is used to share the Subtrace object in the subtracer and in the
	// Internal::Call record.
	fn shallow_clone(&self) -> Self {
		Self {
			contract: self.contract,
			trace: self.trace.clone(),
		}
	}

	fn drain(self) -> FullTracerCallTrace {
		let mut v = self.trace.lock().unwrap();
		let rt = v.drain(..).map(|x| x.drain()).collect();
		FullTracerCallTrace {
			contract: self.contract,
			trace: rt,
		}
	}
}

impl Into<FullExtTracer> for SubTrace {
	fn into(self) -> FullExtTracer {
		FullExtTracer { inner: self }
	}
}

/// Public type for the trace, returned from drain() -- excludes the Arc<Mutex<>>.
#[derive(PartialEq, Debug)]
pub struct FullTracerCallTrace {
	/// `contract` contains the code that is executing the trace.
	pub contract: Address,
	/// `trace` contains the record of the externalities actions executed by the code.
	pub trace: Vec<FullTracerRecord>,
}

/// Each record records the `H256` or `Address` that we are getting information about or
/// modifying.  A `Call` is itself a trace.
#[derive(PartialEq, Debug)]
pub enum FullTracerRecord {
	/// Read location
	Read(H256),
	/// Write location
	Write(H256),
	/// Contract exists
	Exists(Address),
	/// Contract exists and not an empty account (no code, zero nonce, zero balance) (?)
	ExistsNotNull(Address),
	/// Balance read
	Balance(Address),
	/// Subcontract call, which gets its own trace
	Call(FullTracerCallTrace),
}

impl FullExtTracer {
	/// Create a new FullExtTracer to trace the execution.
	pub fn new() -> Self {
		// At the top-level, there is no contract address associated with the trace
		// since the executor just uses it to do a single `call` into the contract
		// being executed.  We use Address::zero() to indicate that this is a top-level
		// subtrace.
		FullExtTracer {
			inner: SubTrace::new(&Address::zero()),
		}
	}

	/// Extract the externalities trace from the FullExtTracer.
	pub fn drain(self) -> FullTracerCallTrace {
		assert!(self.inner.contract == Address::zero());
		let mut trace = self.inner.trace.lock().unwrap();
		assert!(trace.len() == 1);
		match trace.pop().unwrap() {
			Internal::Call(st) => st.drain(),
			_ => {
				panic!("internal error, not a call at top level");
			}
		}
	}
}

/// Format a vector of FullTracerRecord, with comma separators.  This, and the fmt::Display
/// impls below, are primarily used for debugging.
fn trace_fmt(trace: &Vec<FullTracerRecord>, f: &mut fmt::Formatter) -> fmt::Result {
	let mut sep: String = "".into();
	for rec in trace.iter() {
		match write!(f, "{}{}", sep, rec) {
			Err(e) => return Err(e),
			_ => (),
		};
		sep = ", ".into();
	}
	Ok(())
}

impl fmt::Display for FullTracerCallTrace {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match write!(f, "C({}):[", self.contract) {
			Err(e) => Err(e),
			Ok(_) => trace_fmt(&self.trace, f).and_then(|_| write!(f, "]")),
		}
	}
}

impl fmt::Display for FullTracerRecord {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			FullTracerRecord::Read(loc) => write!(f, "R:{}", loc),
			FullTracerRecord::Write(loc) => write!(f, "W:{}", loc),
			FullTracerRecord::Exists(addr) => write!(f, "X:{}", addr),
			FullTracerRecord::ExistsNotNull(addr) => write!(f, "Xnn:{}", addr),
			FullTracerRecord::Balance(addr) => write!(f, "B:{}", addr),
			FullTracerRecord::Call(sub) => write!(f, "Call{}", sub),
		}
	}
}

impl Internal {
	fn drain(self) -> FullTracerRecord {
		match self {
			Internal::Read(loc) => FullTracerRecord::Read(loc),
			Internal::Write(loc) => FullTracerRecord::Write(loc),
			Internal::Exists(addr) => FullTracerRecord::Exists(addr),
			Internal::ExistsNotNull(addr) => FullTracerRecord::ExistsNotNull(addr),
			Internal::Balance(addr) => FullTracerRecord::Balance(addr),
			Internal::Call(st) => FullTracerRecord::Call(st.drain()),
		}
	}
}

impl ExtTracer for FullExtTracer {
	fn trace_storage_at(&self, key: &H256) {
		let mut trace = self.inner.trace.lock().unwrap();

		trace.push(Internal::Read(*key));
	}

	/// Transaction execution writes into persistent state.
	fn trace_set_storage(&self, key: &H256) {
		let mut trace = self.inner.trace.lock().unwrap();

		trace.push(Internal::Write(*key));
	}

	/// Transaction (indirectly) performs an exists query.
	fn trace_exists(&self, address: &Address) {
		let mut trace = self.inner.trace.lock().unwrap();

		trace.push(Internal::Exists(*address));
	}

	/// Transactions (indirectly) performs an exists_and_not_null query.
	fn trace_exists_and_not_null(&self, address: &Address) {
		let mut trace = self.inner.trace.lock().unwrap();

		trace.push(Internal::ExistsNotNull(*address));
	}

	/// Transaction performs an origin_balance or balance query.  Unlike Ext, we do not know
	/// origin address, so it must be provided by Ext implementations.
	fn trace_balance(&self, origin_address: &Address) {
		let mut trace = self.inner.trace.lock().unwrap();

		trace.push(Internal::Balance(*origin_address));
	}

	/// subtracer returns an Ext tracer for use for the context of the sub-transaction call.
	fn subtracer(&mut self, code_address: &Address) -> Self {
		let rv = SubTrace::new(code_address);
		let mut trace = self.inner.trace.lock().unwrap();

		trace.push(Internal::Call(rv.shallow_clone()));
		rv.into()
	}
}
