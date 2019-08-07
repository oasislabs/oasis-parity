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

/// ExtTracer-specific error enum.
pub mod error;
/// ExtTracer trait for tracing Ext (Externalities) calls.
pub mod ext_tracer;
/// FullExtTracer full externalities tracing.
pub mod full_ext_tracer;
/// Concrete class for no-op tracing.
pub mod noop;
// Bloomfilter used internally for counting.
mod bloomfilter;
/// CountingExtTracer that just estimates the sizes of the conflict sets.
pub mod counting_tracer;

pub use self::counting_tracer::CountingTracer;
pub use self::ext_tracer::ExtTracer;
pub use self::full_ext_tracer::{FullExtTracer, FullTracerCallTrace, FullTracerRecord};
pub use self::noop::NoopExtTracer;
