// (c) Oasis Labs.  All right reserved.

// To be open sourced eventually.

use std::cmp::{Ordering, PartialOrd};
use ethereum_types::{Address, H256};

// Contract addr: storage key, balance.
#[derive(Hash, Eq)]
pub struct ParityStorageLocation {
    contract: Address,
    key: H256,
}

impl PartialEq for ParityStorageLocation {
    fn eq(&self, other: &ParityStorageLocation) -> bool {
        self.contract == other.contract && self.key == other.key
    }
}

impl PartialOrd for ParityStorageLocation {
    fn partial_cmp(&self, other: &ParityStorageLocation) -> Option<Ordering> {
        return if self.contract < other.contract {
            Some(Ordering::Less)
        } else if self.contract > other.contract {
            Some(Ordering::Greater)
        } else {
            if self.key < other.key {
                Some(Ordering::Less)
            } else if self.key > other.key {
                Some(Ordering::Greater)
            } else {
                Some(Ordering::Equal)
            }
        }
    }
}

#[derive(Hash, Eq)]
pub enum ParityLocation {
    Balance(Address),
    Storage(ParityStorageLocation),
}

impl PartialEq for ParityLocation {
    fn eq(&self, other: &ParityLocation) -> bool {
        return match self {
            ParityLocation::Balance(my_addr) => match other {
                ParityLocation::Balance(other_addr) => my_addr == other_addr,
                ParityLocation::Storage(_) => false,
            },
            ParityLocation::Storage(s) => match other {
                ParityLocation::Balance(_) => false,
                ParityLocation::Storage(os) => s == os,
            }
        }
    }
}

impl PartialOrd for ParityLocation {
    fn partial_cmp(&self, other: &ParityLocation) -> Option<Ordering> {
        return match self {
            ParityLocation::Balance(my_addr) => match other {
                ParityLocation::Balance(other_addr) => my_addr.partial_cmp(other_addr),
                ParityLocation::Storage(_) => Some(Ordering::Less),
            },
            ParityLocation::Storage(psl) => match other {
                ParityLocation::Balance(_) => Some(Ordering::Greater),
                ParityLocation::Storage(opsl) => psl.partial_cmp(opsl),
            }
        }
    }
}
