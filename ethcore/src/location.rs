// (c) Oasis Labs.  All right reserved.

// To be open sourced eventually.

use std::fmt;
use std::cmp::{Ordering, PartialOrd};
use ethereum_types::{Address, H256};
// use serde::{Deserialize, Deserializer, Serialize, Serializer};

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

impl fmt::Display for ParityStorageLocation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.contract, self.key)
    }
}

// impl Serialize for ParityStorageLocation {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//         where S: Serializer,
//     {
//         let mut buffer = [0u8; 160/8 + 256/8];
//         self.contract.to_big_endian(&mut buffer);
//     }
// }

#[derive(Hash, Eq)]
pub enum ParityLocation {
    Balance(Address),
    Storage(ParityStorageLocation),
}

impl fmt::Display for ParityLocation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParityLocation::Balance(addr) => write!(f, "B({})", addr),
            ParityLocation::Storage(s) => write!(f, "S({})", s)
        }
    }
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
