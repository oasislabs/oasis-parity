// (c) Oasis Labs.  All right reserved.

// To be open sourced eventually.

use std::collections::HashSet;

use location;

// LocationSet is essentially a set of location::ParityLocation values, but potentially with
// one-sided error in membership tests.
//
// We use a trait for LocationSet here because for now, we just use a normal HashSet; in the
// future, however, we may explore the use of a cuckoo or Bloom filter or some other data
// structure to save space, at the expense of occasionally erroneously declaring the
// possibility of a r/w or w/w conflict when there aren't any.  For transaction scheduling,
// one-sided error is fine -- it just leads to slightly less parallelism, without affecting
// correctness.
pub trait LocationSet {
    fn add(&mut self, loc: location::ParityLocation) -> bool;

    // may_contain is like contains, but with one-sided error.  It is okay to return true even
    // if the location was never added, but not okay to return false if the location had been
    // added.
    fn may_contain(&self, loc: &location::ParityLocation) -> bool;

    fn size(&self) -> usize;

    // Delete is not used.  Merge, ConsistentFind, etc are used by the transaction scheduler
    // and not for gathering conflict sets.
}

struct LocationSetSimple {
    locs: HashSet<location::ParityLocation>,
}

impl LocationSetSimple {
    fn new() -> Self {
        Self { locs: HashSet::new() }
    }

    fn add(&mut self, loc: location::ParityLocation) -> bool {
        self.locs.insert(loc)
    }

    fn may_contain(&self, loc: &location::ParityLocation) -> bool {
        self.locs.contains(loc)
    }

    fn size(&self) -> usize {
        self.locs.len()
    }
}
