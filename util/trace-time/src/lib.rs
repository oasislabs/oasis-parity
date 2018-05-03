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

//! Performance timer with logging

extern crate ansi_term;
#[macro_use]
pub extern crate log;

use std::time::Instant;
use ansi_term::Colour;

#[macro_export]
macro_rules! trace_time {
	($name: expr) => {
		let _timer = if log_enabled!(target: "perf", $crate::log::LogLevel::Debug) {
			Some($crate::PerfTimer::new($name))
		} else {
			None
		};
	}
}

/// Performance timer with logging. Starts measuring time in the constructor, prints
/// elapsed time in the destructor or when `stop` is called.
pub struct PerfTimer {
	name: &'static str,
	start: Instant,
}

impl PerfTimer {
	/// Create an instance with given name.
	pub fn new(name: &'static str) -> PerfTimer {
		PerfTimer {
			name,
			start: Instant::now(),
		}
	}
}

impl Drop for PerfTimer {
	fn drop(&mut self) {
		let elapsed = self.start.elapsed();
		let ms = elapsed.subsec_nanos() as f32 / 1_000_000.0 +
				 elapsed.as_secs() as f32 * 1_000.0;

		if ms > 300.0 {
			debug!(target: "perf", "{}", Colour::Red.bold().paint(format!("{}: {:.2}ms", self.name, ms)));
		} else {
			trace!(target: "perf", "{}: {:.2}ms", self.name, ms);
		}
	}
}
