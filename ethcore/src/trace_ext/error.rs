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

#[derive(Debug, Clone, PartialEq)]
/// Errors that arise from externalities tracers.  Which errors may occur depends on the
/// particular ExtTracer implementation used.
pub enum Error {
	/// When taking the `intersect` of two Bloom filters, the bitmap size must match.
	BitmapSizeMismatch,
	/// When taking the `intersect` of two Bloom filters, the number of statistically
	/// independent hash functions used must match.
	NumberOfHashFnMismatch,
}
