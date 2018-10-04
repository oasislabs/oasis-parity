use hashdb::*;
use ethereum_types::H256;

use super::{Trie, TrieItem, TrieMut, TrieError, TrieIterator, Query};

pub struct PassthroughDB<'db> {
    col: Option<u32>,
    mapped: MappedKeyValueDB,
    root: &'db H256,
}

impl<'db> PassthroughDB<'db> {
    pub fn new(col: Option<u32>, db: &'db HashDB, root: &'db H256) -> Self {
        Self {
            col,
            mapped: db.get_passthrough_kvdb().expect("PassthroughDB requires a kvdb backing store"),
            root,
        }
    }
}

impl<'db> Trie for PassthroughDB<'db> {
    fn iter<'a>(&'a self) -> super::Result<Box<TrieIterator<Item = TrieItem> + 'a>> {
        unimplemented!();
    }

    fn root(&self) -> &H256 {
        self.root
    }

    fn get_with<'a, 'key, Q: Query>(&'a self, key: &'key [u8], query: Q) -> super::Result<Option<Q::Item>>
        where 'a: 'key
    {
        let key = &(self.mapped.mapper)(key);
        self.mapped.db.get(self.col, key)
            .map(|value| value.map(|value| query.decode(&value)))
            .map_err(|_error| Box::new(TrieError::InvalidStateRoot(*self.root)))
    }
}

pub struct PassthroughDBMut<'db> {
    col: Option<u32>,
    mapped: MappedKeyValueDB,
    hashdb: &'db mut HashDB,
    root: &'db mut H256,
}

impl<'db> PassthroughDBMut<'db> {
    pub fn new(col: Option<u32>, db: &'db mut HashDB, root: &'db mut H256) -> Self {
        Self {
            col,
            mapped: db.get_passthrough_kvdb().expect("PassthroughDB requires a kvdb backing store"),
            hashdb: db,
            root,
        }
    }

    pub fn from_existing(col: Option<u32>, db: &'db mut HashDB, root: &'db mut H256) -> super::Result<Self> {
        Ok(Self::new(col, db, root))
    }
}

impl<'db> TrieMut for PassthroughDBMut<'db> {
    fn root(&mut self) -> &H256 {
        self.root
    }

    fn is_empty(&self) -> bool {
        self.root == &H256::zero()
    }

    fn get<'a, 'key>(&'a self, key: &'key [u8]) -> super::Result<Option<DBValue>> where 'a: 'key {
        let key = &(self.mapped.mapper)(key);
        self.mapped.db.get(self.col, key).map_err(|_error| Box::new(TrieError::InvalidStateRoot(*self.root)))
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> super::Result<Option<DBValue>> {
        let key = &(self.mapped.mapper)(key);
        let previous = TrieMut::get(self, key);
        let mut tx = self.mapped.db.transaction();
        if value.is_empty() {
            tx.delete(self.col, key);
        } else {
            tx.put(self.col, key, value);
        }
        self.mapped.db.write(tx).map_err(|_error| Box::new(TrieError::InvalidStateRoot(*self.root)))?;
        // TODO: Don't do this on every update.
        *self.root = self.hashdb.insert(&[0x00]);

        previous
    }

    fn remove(&mut self, key: &[u8]) -> super::Result<Option<DBValue>> {
        self.insert(key, &[])
    }
}
