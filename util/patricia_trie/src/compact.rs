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

//! In-memory trie representation.

use super::{TrieError, TrieMut};

use hashdb::HashDB;
use bytes::ToPretty;
use hashdb::DBValue;

use std::collections::{HashSet, VecDeque};
use std::mem;
use std::ops::Index;
use ethereum_types::H256;
use slicable::{Slicable, Input};

// For lookups into the Node storage buffer.
#[derive(Debug, Clone)]
struct StorageHandle(usize);

// Handles to nodes in the trie.
#[derive(Debug, Clone)]
enum NodeHandle {
	/// Loaded into memory.
	InMemory(StorageHandle),
	/// Either a hash or an inline node
	Hash(H256),
	/// Built-in
	Embedded([u8; 32]),
}

impl From<StorageHandle> for NodeHandle {
	fn from(handle: StorageHandle) -> Self {
		NodeHandle::InMemory(handle)
	}
}

impl From<H256> for NodeHandle {
	fn from(hash: H256) -> Self {
		NodeHandle::Hash(hash)
	}
}

type PartialKey = Vec<u8>;
type Value = Vec<u8>;

/// Node types in the Trie.
#[derive(Debug)]
enum Node {
	/// Empty node.
	Empty,
	/// Value node.
	Value(Value),
	/// A branch has up to 16 children and an optional value.
	Branch(Vec<(PartialKey, NodeHandle)>),
	Full(Vec<NodeHandle>)
}

impl Node {
	fn into_sliced<F>(self, v: &mut Vec<u8>, mut child_cb: F)
	where F: FnMut(NodeHandle, &mut Vec<u8>) {
		match self {
			Node::Value(value) => {
				v.push(NodeKind::Value as u8);
				value.using_encoded(|s| v.extend(s));
			},
			Node::Branch(nodes) => {
				v.push(NodeKind::Branch as u8);
				(nodes.len() as u32).using_encoded(|s| v.extend(s));
				for (key, handle) in nodes.into_iter() {
					key.using_encoded(|s| v.extend(s));
					child_cb(handle, v);
				}
			},
			Node::Full(nodes) => {
				v.push(NodeKind::Full as u8);
				for handle in nodes.into_iter() {
					child_cb(handle, v);
				}
			},
			Node::Empty => {
				v.push(NodeKind::Empty as u8);
			}
		}
	}

	// load an inline node into memory or get the hash to do the lookup later.
	fn inline_or_hash(node: &[u8]) -> NodeHandle {
		Self::try_decode_hash(&node)
			.map(NodeHandle::Hash)
			.unwrap_or_else(|| {
				let mut data = [0; 32];
				&mut data[0..node.len()].copy_from_slice(node);
				NodeHandle::Embedded(data)
			})
	}

	// decode a node from bytes without getting its children.
	fn from_sliced<I: Input>(value: &mut I) -> Self {
		match i8::decode(value) {
			Some(x) if x == NodeKind::Empty as i8 => {
				Node::Empty
			},
			Some(x) if x == NodeKind::Value as i8 => {
				Node::Value(Slicable::decode(value).unwrap())
			},
			Some(x) if x == NodeKind::Branch as i8 => {
				let len: u32 = Slicable::decode(value).unwrap();
				let mut children = Vec::with_capacity(len as usize);
				for _ in 0 .. len {
					let key = Slicable::decode(value).unwrap();
					let data: Vec<u8> = Slicable::decode(value).unwrap();
					let handle = Self::inline_or_hash(&data);
					children.push((key, handle));
				}
				Node::Branch(children)
			},
			Some(x) if x == NodeKind::Full as i8 => {
				let mut children = Vec::with_capacity(256);
				for _ in 0 .. 256 {
					let data: Vec<u8> = Slicable::decode(value).unwrap();
					let handle = Self::inline_or_hash(&data);
					children.push(handle);
				}
				Node::Full(children)
			},
			Some(x) => panic!("Encoding is invalid: {}", x),
			None => panic!("Encoding is none."),
		}
	}

	fn try_decode_hash(node_data: &[u8]) -> Option<H256> {
		if node_data.len() == 32 {
			Some(H256::from(node_data))
		} else {
			None
		}
	}

	fn maybe_full(self) -> Node {
		match self {
			Node::Branch(children) => {
				if children.len() == 256 && children.iter().all(|&(ref k, _)| k.len() == 1) {
					println!("BRANCH -> FULL");
					for i in 0..256 {
						assert_eq!(&children[i].0[..1], &[ i as u8 ]);
					}
					let children = children.into_iter().map(|(_, node)| node).collect();
					return Node::Full(children);
				} else {
					Node::Branch(children)
				}
			},
			node @ _ => node,
		}
	}
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i8)]
enum NodeKind {
	Empty = 1,
	Value = 2,
	Branch = 3,
	Full = 4,
}

// post-inspect action.
enum Action {
	// Replace a node with a new one.
	Replace(Node),
	// Restore the original node. This trusts that the node is actually the original.
	Restore(Node),
	// if it is a new node, just clears the storage.
	Delete,
}

// post-insert action. Same as action without delete
enum InsertAction {
	// Replace a node with a new one.
	Replace(Node),
	// Restore the original node.
	Restore(Node),
}

impl InsertAction {
	fn into_action(self) -> Action {
		match self {
			InsertAction::Replace(n) => Action::Replace(n),
			InsertAction::Restore(n) => Action::Restore(n),
		}
	}
}

// What kind of node is stored here.
enum Stored {
	// A new node.
	New(Node),
	// A cached node, loaded from the DB.
	Cached(Node, H256),
}

/// Compact and cache-friendly storage for Trie nodes.
struct NodeStorage {
	nodes: Vec<Stored>,
	free_indices: VecDeque<usize>,
}

impl NodeStorage {
	/// Create a new storage.
	fn empty() -> Self {
		NodeStorage {
			nodes: Vec::new(),
			free_indices: VecDeque::new(),
		}
	}

	/// Allocate a new node in the storage.
	fn alloc(&mut self, stored: Stored) -> StorageHandle {
		if let Some(idx) = self.free_indices.pop_front() {
			self.nodes[idx] = stored;
			StorageHandle(idx)
		} else {
			self.nodes.push(stored);
			StorageHandle(self.nodes.len() - 1)
		}
	}

	/// Remove a node from the storage, consuming the handle and returning the node.
	fn destroy(&mut self, handle: StorageHandle) -> Stored {
		let idx = handle.0;

		self.free_indices.push_back(idx);
		mem::replace(&mut self.nodes[idx], Stored::New(Node::Empty))
	}

	fn get_mut(&mut self, handle: &StorageHandle) -> &mut Node {
		match self.nodes[handle.0] {
			Stored::New(ref mut node) => node,
			Stored::Cached(ref mut node, _) => node,
		}
	}
}

impl<'a> Index<&'a StorageHandle> for NodeStorage {
	type Output = Node;

	fn index(&self, handle: &'a StorageHandle) -> &Node {
		match self.nodes[handle.0] {
			Stored::New(ref node) => node,
			Stored::Cached(ref node, _) => node,
		}
	}
}

/// A `Trie` implementation using a generic `HashDB` backing database.
///
/// Use it as a `TrieMut` trait object. You can use `db()` to get the backing database object.
/// Note that changes are not committed to the database until `commit` is called.
/// Querying the root or dropping the trie will commit automatically.
///
/// # Example
/// ```
/// extern crate patricia_trie as trie;
/// extern crate keccak_hash;
/// extern crate hashdb;
/// extern crate memorydb;
/// extern crate ethereum_types;
///
/// use keccak_hash::KECCAK_NULL_RLP;
/// use trie::*;
/// use hashdb::*;
/// use memorydb::*;
/// use ethereum_types::H256;
///
/// fn main() {
///   let mut memdb = MemoryDB::new();
///   let mut root = H256::new();
///   let mut t = TrieDBMut::new(&mut memdb, &mut root);
///   assert!(t.is_empty());
///   assert_eq!(*t.root(), KECCAK_NULL_RLP);
///   t.insert(b"foo", b"bar").unwrap();
///   assert!(t.contains(b"foo").unwrap());
///   assert_eq!(t.get(b"foo").unwrap().unwrap(), DBValue::from_slice(b"bar"));
///   t.remove(b"foo").unwrap();
///   assert!(!t.contains(b"foo").unwrap());
/// }
/// ```
pub struct TrieDBMut<'a> {
	storage: NodeStorage,
	db: &'a mut HashDB,
	root: &'a mut H256,
	root_handle: NodeHandle,
	death_row: HashSet<H256>,
	/// The number of hash operations this trie has performed.
	/// Note that none are performed until changes are committed.
	hash_count: usize,
}

impl<'a> TrieDBMut<'a> {
	/// Create a new trie with backing database `db` and empty `root`.
	pub fn new(db: &'a mut HashDB, root: &'a mut H256) -> Self {
		let mut storage = NodeStorage::empty();
		let root_handle = NodeHandle::InMemory(storage.alloc(Stored::New(Node::Empty)));
		TrieDBMut {
			storage: storage,
			db: db,
			root: root,
			root_handle: root_handle,
			death_row: HashSet::new(),
			hash_count: 0,
		}
	}

	/// Create a new trie with the backing database `db` and `root.
	/// Returns an error if `root` does not exist.
	pub fn from_existing(db: &'a mut HashDB, root: &'a mut H256) -> super::Result<Self> {
		if !db.contains(root) {
			return Err(Box::new(TrieError::InvalidStateRoot(*root)));
		}

		let root_handle = NodeHandle::Hash(*root);
		Ok(TrieDBMut {
			storage: NodeStorage::empty(),
			db: db,
			root: root,
			root_handle: root_handle,
			death_row: HashSet::new(),
			hash_count: 0,
		})
	}
	/// Get the backing database.
	pub fn db(&self) -> &HashDB {
		self.db
	}

	/// Get the backing database mutably.
	pub fn db_mut(&mut self) -> &mut HashDB {
		self.db
	}

	// cache a node by hash
	fn cache(&mut self, hash: H256) -> super::Result<StorageHandle> {
		let node_bytes = self.db.get(&hash).ok_or_else(|| Box::new(TrieError::IncompleteDatabase(hash)))?;
		let node = self.cache_node_data(&node_bytes[..]);
		Ok(self.storage.alloc(Stored::Cached(node, hash)))
	}

	// cache a node by hash
	fn cache_node_data(&mut self, mut node_bytes: &[u8]) -> Node {
		let node = Node::from_sliced(&mut node_bytes);
		let node = match node {
			Node::Branch(mut children) => {
				for &mut (_, ref mut n) in children.iter_mut() {
					if let NodeHandle::Embedded(data) = *n {
						let cached = self.cache_node_data(&data);
						*n = NodeHandle::InMemory(self.storage.alloc(Stored::New(cached)));
					}
				}
				Node::Branch(children)
			},
			_ => node,
		};
		node
	}
	// inspect a node, choosing either to replace, restore, or delete it.
	// if restored or replaced, returns the new node along with a flag of whether it was changed.
	fn inspect<F>(&mut self, stored: Stored, inspector: F) -> super::Result<Option<(Stored, bool)>>
	where F: FnOnce(&mut Self, Node) -> super::Result<Action> {
		Ok(match stored {
			Stored::New(node) => match inspector(self, node)? {
				Action::Restore(node) => Some((Stored::New(node), false)),
				Action::Replace(node) => Some((Stored::New(node), true)),
				Action::Delete => None,
			},
			Stored::Cached(node, hash) => match inspector(self, node)? {
				Action::Restore(node) => Some((Stored::Cached(node, hash), false)),
				Action::Replace(node) => {
					self.death_row.insert(hash);
					Some((Stored::New(node), true))
				}
				Action::Delete => {
					self.death_row.insert(hash);
					None
				}
			},
		})
	}

	// walk the trie, attempting to find the key's node.
	fn lookup(&self, mut partial: PartialKey, handle: &NodeHandle) -> super::Result<Option<DBValue>>
	{
		let mut handle = handle.clone();
		'next: loop {
			let mut _node_from_bytes: Option<Node> = None;
			let node = match handle {
				NodeHandle::Hash(ref hash) => {
					let node_bytes = self.db.get(&hash).ok_or_else(|| Box::new(TrieError::IncompleteDatabase(*hash)))?;
					_node_from_bytes = Some(Node::from_sliced(&mut &node_bytes[..]));
					_node_from_bytes.as_ref().unwrap()
				},
				NodeHandle::InMemory(ref handle) => &self.storage[handle],
				NodeHandle::Embedded(ref bytes) => {
					_node_from_bytes = Some(Node::from_sliced(&mut &bytes[..]));
					_node_from_bytes.as_ref().unwrap()
				}
			};
			match *node {
				Node::Empty => {
					trace!(target: "trie", "lookup: EMPTY");
					return Ok(None)
				},
				Node::Value(ref value) => {
					trace!(target: "trie", "lookup: VALUE, partial={:?}", partial);
					if !partial.is_empty() {
						return Ok(None)
					}
					return Ok(Some(DBValue::from_slice(&value)));
				}
				Node::Branch(ref children) => {
					trace!(target: "trie", "lookup: BRANCH partial={:?}", partial);
					if partial.is_empty() {
						trace!(target: "trie", "lookup: BRANCH END-NOT-FOUND");
						return Ok(None);
					}
					// TODO: binary search
					for &(ref key, ref child) in children.iter() {
						trace!(target: "trie", "lookup: partial={:?}, key={:?}", partial, key);
						if partial.starts_with(key) {
							trace!(target: "trie", "lookup: BRANCH descent");
							handle = child.clone();
							partial = PartialKey::from(&partial[key.len()..]);
							continue 'next;
						}
					}
					trace!(target: "trie", "lookup: BRANCH NOT-FOUND");
					return Ok(None)
				}
				Node::Full(ref children) => {
					trace!(target: "trie", "lookup: FULL partial={:?}", partial);
					if partial.is_empty() {
						trace!(target: "trie", "lookup: FULL END-NOT-FOUND");
						return Ok(None);
					}
					trace!(target: "trie", "lookup: BRANCH descent");
					handle = children[partial[0] as usize].clone();
					partial = PartialKey::from(&partial[1..]);
				}
			}
		}
	}

	/// insert a key, value pair into the trie, creating new nodes if necessary.
	fn insert_at(&mut self, handle: NodeHandle, partial: PartialKey, value: Value, old_val: &mut Option<Value>)
		-> super::Result<(StorageHandle, bool)>
	{
		let h = match handle {
			NodeHandle::InMemory(h) => h,
			NodeHandle::Hash(h) => self.cache(h)?,
			NodeHandle::Embedded(_) => panic!("Inserting into embedded node"),
		};
		let stored = self.storage.destroy(h);
		let (new_stored, changed) = self.inspect(stored, move |trie, stored| {
			trie.insert_inspector(stored, partial, value, old_val).map(|a| a.into_action())
		})?.expect("Insertion never deletes.");

		Ok((self.storage.alloc(new_stored), changed))
	}

	/// the insertion inspector.
	fn insert_inspector(&mut self, node: Node, partial: PartialKey, value: Value, old_val: &mut Option<Value>)
		-> super::Result<InsertAction>
	{
		let empty_key = partial.is_empty();
		trace!(target: "trie", "augmented (partial: {:?}, value: {:?})", partial, value.pretty());

		Ok(match node {
			Node::Empty => {
				trace!(target: "trie", "empty: COMPOSE");
				let value = NodeHandle::InMemory(self.storage.alloc(Stored::New(Node::Value(value))));
				let mut children = vec![(partial, value)];
				InsertAction::Replace(Node::Branch(children))
			}
			Node::Value(stored_value) => {
				if empty_key {
					let unchanged = stored_value == value;
					*old_val = Some(stored_value);

					match unchanged {
						// unchanged. restore
						true => return Ok(InsertAction::Restore(Node::Value(value))),
						false => return Ok(InsertAction::Replace(Node::Value(value))),
					}
				}
				panic!("Inserting into a value with a longer key");
			}
			Node::Branch(mut children) => {
				trace!(target: "trie", "branch: ROUTE,AUGMENT");
				assert!(!empty_key);
				let partial_char = partial[0];
				let (exists, index) = match children.binary_search_by(|&(ref c, _)| c[0].cmp(&partial_char)) {
					Ok(index) => (true, index),
					Err(index) => (false, index),
				};

				if children.is_empty() || !exists {
					// matching child not found, insert it
					trace!(target: "trie", "branch: INSERT NEW at {}", index);
					let value = NodeHandle::InMemory(self.storage.alloc(Stored::New(Node::Value(value))));
					assert!(!partial.is_empty());
					children.insert(index, (partial, value));
					return Ok(InsertAction::Replace(Node::Branch(children).maybe_full()));
				}
				let key = children[index].0.clone();
				let node = children[index].1.clone();
				let mut split_at = 0;
				while split_at < key.len() && split_at < partial.len() && key[split_at] == partial[split_at] {
					split_at = split_at + 1;
				}

				if split_at == key.len() {
					trace!(target: "trie", "branch: DESCENT");
					let mid = PartialKey::from(&partial[key.len()..]);
					let (new_child, changed) = self.insert_at(node, mid, value, old_val)?;
					assert!(!key.is_empty());
					children[index] = (key, NodeHandle::InMemory(new_child));
					match changed {
						true => return Ok(InsertAction::Replace(Node::Branch(children))),
						false => return Ok(InsertAction::Restore(Node::Branch(children))),
					}
				} else {
					let new_root_key = PartialKey::from(&partial[..split_at]);
					let value_key = PartialKey::from(&partial[split_at..]);
					let old_key = PartialKey::from(&key[split_at..]);
					let old_node = children[index].1.clone();
					let value = NodeHandle::InMemory(self.storage.alloc(Stored::New(Node::Value(value))));
					let ((left_key, left_node), (right_key, right_node)) = if key[split_at] < partial[split_at] {
						((old_key, old_node), (value_key, value))
					} else {
						((value_key, value), (old_key, old_node))
					};
					trace!(target: "trie", "branch: SPLIT, root={:?}, left={:?}. right={:?}", new_root_key, left_key, right_key);
					let branch = NodeHandle::InMemory(self.storage.alloc(Stored::New(Node::Branch(vec![(left_key, left_node), (right_key, right_node)]))));
					assert!(!new_root_key.is_empty());
					children[index] = (new_root_key, branch);
					InsertAction::Replace(Node::Branch(children).maybe_full())
				}
			},
			Node::Full(mut children) => {
				assert!(!empty_key);
				let partial_char = partial[0];
				let node = children[partial_char as usize].clone();
				trace!(target: "trie", "full: DESCENT");
				let mid = PartialKey::from(&partial[1..]);
				let (new_child, changed) = self.insert_at(node, mid, value, old_val)?;
				children[partial_char as usize] = NodeHandle::InMemory(new_child);
				match changed {
					true => return Ok(InsertAction::Replace(Node::Full(children))),
					false => return Ok(InsertAction::Restore(Node::Full(children))),
				}
			}
		})
	}

	/// Remove a node from the trie based on key.
	fn remove_at(&mut self, handle: NodeHandle, partial: PartialKey, old_val: &mut Option<Value>)
		-> super::Result<Option<(StorageHandle, bool)>>
	{
		let stored = match handle {
			NodeHandle::InMemory(h) => self.storage.destroy(h),
			NodeHandle::Hash(h) => {
				let handle = self.cache(h)?;
				self.storage.destroy(handle)
			},
			NodeHandle::Embedded(_) => panic!("Removing at embedded node"),
		};

		let opt = self.inspect(stored, move |trie, node| trie.remove_inspector(node, partial, old_val))?;

		Ok(opt.map(|(new, changed)| (self.storage.alloc(new), changed)))
	}

	/// the removal inspector
	fn remove_inspector(&mut self, node: Node, partial: PartialKey, old_val: &mut Option<Value>) -> super::Result<Action> {
		Ok(match (node, partial.is_empty()) {
			(Node::Empty, _) => Action::Delete,
			(Node::Branch(c), true) => Action::Restore(Node::Branch(c)),
			(Node::Full(c), true) => Action::Restore(Node::Full(c)),
			(Node::Value(val), true) => {
				*old_val = Some(val);
				Action::Delete
			}
			(Node::Value(_), false) => {
				panic!("Key is too long");
			}
			(Node::Branch(mut children), false) => {
				let partial_char = partial[0];
				let (exists, index) = match children.binary_search_by(|&(ref c, _)| c[0].cmp(&partial_char)) {
					Ok(index) => (true, index),
					Err(index) => (false, index),
				};

				if children.is_empty() || !exists {
					return Ok(Action::Restore(Node::Branch(children)));
				}

				let key = children[index].0.clone();
				if !partial.starts_with(&key) {
					return Ok(Action::Restore(Node::Branch(children)));
				}
				let partial = PartialKey::from(&partial[key.len()..]);
				trace!(target: "trie", "removing value out of branch child, partial={:?}", partial);
				match self.remove_at(children[index].1.clone(), partial, old_val)? {
					Some((new, changed)) => {
						if let Node::Branch(ref mut subchildren) = *self.storage.get_mut(&new) {
							if subchildren.len() == 1 {
								// single child, delete it and merge into this node
								// TODO: add to deleted list
								//self.death_row.insert(hash);
								let (sub_key, sub) = subchildren.pop().unwrap();
								let mut new_key = key;
								new_key.extend_from_slice(&sub_key);
								children[index] = (new_key, sub);
								return Ok(Action::Replace(Node::Branch(children)))
							}
						}
						children[index] = (key, new.into());
						match changed {
							// child was changed, so we were too.
							true => Action::Replace(Node::Branch(children)),
							// unchanged, so we are too.
							false => Action::Restore(Node::Branch(children)),
						}
					},
					None => {
						children.remove(index);
						// the child we took was deleted.
						trace!(target: "trie", "branch child deleted");
						Action::Replace(Node::Branch(children))
					}
				}
			}
			(Node::Full(_children), false) => {
				unimplemented!();
			}
		})
	}

	/// Commit the in-memory changes to disk, freeing their storage and
	/// updating the state root.
	pub fn commit(&mut self) {
		trace!(target: "trie", "Committing trie changes to db.");

		// always kill all the nodes on death row.
		trace!(target: "trie", "{:?} nodes to remove from db", self.death_row.len());
		for hash in self.death_row.drain() {
			self.db.remove(&hash);
		}

		let handle = match self.root_handle() {
			NodeHandle::Hash(_) => return, // no changes necessary.
			NodeHandle::Embedded(_) => return, // no changes necessary.
			NodeHandle::InMemory(h) => h,
		};

		match self.storage.destroy(handle) {
			Stored::New(node) => {
				let mut bytes = Vec::new();
				node.into_sliced(&mut bytes, |child, stream| self.commit_node(child, stream));
				*self.root = self.db.insert(&bytes);
				self.hash_count += 1;

				trace!(target: "trie", "root node bytes: {:?}", (&bytes[..]).pretty());
				self.root_handle = NodeHandle::Hash(*self.root);
			}
			Stored::Cached(node, hash) => {
				// probably won't happen, but update the root and move on.
				*self.root = hash;
				self.root_handle = NodeHandle::InMemory(self.storage.alloc(Stored::Cached(node, hash)));
			}
		}
	}

	/// commit a node, hashing it, committing it to the db,
	/// and writing it to the byte stream as necessary.
	fn commit_node(&mut self, handle: NodeHandle, stream: &mut Vec<u8>) {
		match handle {
			NodeHandle::Embedded(_) => panic!("Commiting embedded node"),
			NodeHandle::Hash(h) => (&h[..]).using_encoded(|s| stream.extend(s)),
			NodeHandle::InMemory(h) => match self.storage.destroy(h) {
				Stored::Cached(_, h) => (&h[..]).using_encoded(|s| stream.extend(s)),
				Stored::New(node) => {
					let mut bytes = Vec::new();
					node.into_sliced(&mut bytes, |child, stream| self.commit_node(child, stream));
					if bytes.len() >= 32 {
						let hash = self.db.insert(&bytes);
						self.hash_count += 1;
						(&hash[..]).using_encoded(|s| stream.extend(s));
					} else {
						bytes.using_encoded(|s| stream.extend(s));
					}
				}
			}
		};
	}

	// a hack to get the root node's handle
	fn root_handle(&self) -> NodeHandle {
		match self.root_handle {
			NodeHandle::Hash(h) => NodeHandle::Hash(h),
			NodeHandle::InMemory(StorageHandle(x)) => NodeHandle::InMemory(StorageHandle(x)),
			NodeHandle::Embedded(_) => panic!("Embedded root node"),
		}
	}
}

impl<'a> TrieMut for TrieDBMut<'a> {
	fn root(&mut self) -> &H256 {
		self.commit();
		self.root
	}

	fn is_empty(&self) -> bool {
		match self.root_handle {
			NodeHandle::Hash(_h) => false, //TODO: check for empty node hash
			NodeHandle::InMemory(ref h) => match self.storage[h] {
				Node::Empty => true,
				_ => false,
			},
			NodeHandle::Embedded(_) => panic!("Embedded root node"),
		}
	}

	fn get<'x, 'key>(&'x self, key: &'key [u8]) -> super::Result<Option<DBValue>> where 'x: 'key {
		self.lookup(PartialKey::from(key), &self.root_handle)
	}


	fn insert(&mut self, key: &[u8], value: &[u8]) -> super::Result<Option<DBValue>> {
		if value.is_empty() { return self.remove(key) }

		let mut old_val = None;

		trace!(target: "trie", "insert: key={:?}, value={:?}", key.pretty(), value.pretty());

		let root_handle = self.root_handle();
		let (new_handle, changed) = self.insert_at(
			root_handle,
			PartialKey::from(key),
			value.into(),
			&mut old_val,
		)?;

		trace!(target: "trie", "insert: altered trie={}", changed);
		self.root_handle = NodeHandle::InMemory(new_handle);

		Ok(old_val.map(|v| DBValue::from_slice(&v)))
	}

	fn remove(&mut self, key: &[u8]) -> super::Result<Option<DBValue>> {
		trace!(target: "trie", "remove: key={:?}", key.pretty());

		let root_handle = self.root_handle();
		let key = PartialKey::from(key);
		let mut old_val = None;

		match self.remove_at(root_handle, key, &mut old_val)? {
			Some((handle, changed)) => {
				trace!(target: "trie", "remove: altered trie={}", changed);
				self.root_handle = NodeHandle::InMemory(handle);
			}
			None => {
				trace!(target: "trie", "remove: obliterated trie");
				self.root_handle = NodeHandle::InMemory(self.storage.alloc(Stored::New(Node::Empty)));
			}
		}

		Ok(old_val.map(|v| DBValue::from_slice(&v)))
	}
}

impl<'a> Drop for TrieDBMut<'a> {
	fn drop(&mut self) {
		self.commit();
	}
}

#[cfg(test)]
mod tests {
	extern crate triehash;

	use self::triehash::trie_root;
	use hashdb::*;
	use memorydb::*;
	use super::*;
	use keccak::{KECCAK_NULL_RLP, keccak};
	use super::super::TrieMut;
	use standardmap::*;

	#[test]
	fn compact() {
		::ethcore_logger::init_log();
		let mut memdb = MemoryDB::new();
		let mut root = H256::new();
		let mut t = TrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		assert_eq!(&t.get(&[0x01u8, 0x23]).unwrap().unwrap()[..], &[0x01u8, 0x23]);
	}

	#[test]
	fn init() {
		let mut memdb = MemoryDB::new();
		let mut root = H256::new();
		let mut t = TrieDBMut::new(&mut memdb, &mut root);
		assert_eq!(*t.root(), KECCAK_NULL_RLP);
	}

	#[test]
	fn insert_on_empty() {
		let mut memdb = MemoryDB::new();
		let mut root = H256::new();
		let mut t = TrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		assert_eq!(&t.get(&[0x01u8; 0x23]).unwrap().unwrap()[..], &[0x01u8, 0x23]);
	}

	#[test]
	fn remove_to_empty() {
		let big_value = b"00000000000000000000000000000000";

		let mut memdb = MemoryDB::new();
		let mut root = H256::new();
		let mut t1 = TrieDBMut::new(&mut memdb, &mut root);
		t1.insert(&[0x01, 0x23], big_value).unwrap();
		t1.insert(&[0x01, 0x34], big_value).unwrap();
		let mut memdb2 = MemoryDB::new();
		let mut root2 = H256::new();
		let mut t2 = TrieDBMut::new(&mut memdb2, &mut root2);
		t2.insert(&[0x01], big_value).unwrap();
		t2.insert(&[0x01, 0x23], big_value).unwrap();
		t2.insert(&[0x01, 0x34], big_value).unwrap();
		t2.remove(&[0x01]).unwrap();
	}

	#[test]
	fn insert_replace_root() {
		let mut memdb = MemoryDB::new();
		let mut root = H256::new();
		let mut t = TrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		t.insert(&[0x01u8, 0x23], &[0x23u8, 0x45]).unwrap();
		assert_eq!(*t.root(), trie_root(vec![ (vec![0x01u8, 0x23], vec![0x23u8, 0x45]) ]));
	}

	#[test]
	fn insert_make_branch_root() {
		let mut memdb = MemoryDB::new();
		let mut root = H256::new();
		let mut t = TrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		t.insert(&[0x11u8, 0x23], &[0x11u8, 0x23]).unwrap();
		assert_eq!(*t.root(), trie_root(vec![
			(vec![0x01u8, 0x23], vec![0x01u8, 0x23]),
			(vec![0x11u8, 0x23], vec![0x11u8, 0x23])
		]));
	}

	#[test]
	fn insert_into_branch_root() {
		let mut memdb = MemoryDB::new();
		let mut root = H256::new();
		let mut t = TrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		t.insert(&[0xf1u8, 0x23], &[0xf1u8, 0x23]).unwrap();
		t.insert(&[0x81u8, 0x23], &[0x81u8, 0x23]).unwrap();
		assert_eq!(*t.root(), trie_root(vec![
			(vec![0x01u8, 0x23], vec![0x01u8, 0x23]),
			(vec![0x81u8, 0x23], vec![0x81u8, 0x23]),
			(vec![0xf1u8, 0x23], vec![0xf1u8, 0x23]),
		]));
	}

	#[test]
	fn insert_value_into_branch_root() {
		let mut memdb = MemoryDB::new();
		let mut root = H256::new();
		let mut t = TrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		t.insert(&[], &[0x0]).unwrap();
		assert_eq!(*t.root(), trie_root(vec![
			(vec![], vec![0x0]),
			(vec![0x01u8, 0x23], vec![0x01u8, 0x23]),
		]));
	}

	#[test]
	fn insert_split_leaf() {
		let mut memdb = MemoryDB::new();
		let mut root = H256::new();
		let mut t = TrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		t.insert(&[0x01u8, 0x34], &[0x01u8, 0x34]).unwrap();
		assert_eq!(*t.root(), trie_root(vec![
			(vec![0x01u8, 0x23], vec![0x01u8, 0x23]),
			(vec![0x01u8, 0x34], vec![0x01u8, 0x34]),
		]));
	}

	#[test]
	fn insert_split_extenstion() {
		let mut memdb = MemoryDB::new();
		let mut root = H256::new();
		let mut t = TrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01, 0x23, 0x45], &[0x01]).unwrap();
		t.insert(&[0x01, 0xf3, 0x45], &[0x02]).unwrap();
		t.insert(&[0x01, 0xf3, 0xf5], &[0x03]).unwrap();
		assert_eq!(*t.root(), trie_root(vec![
			(vec![0x01, 0x23, 0x45], vec![0x01]),
			(vec![0x01, 0xf3, 0x45], vec![0x02]),
			(vec![0x01, 0xf3, 0xf5], vec![0x03]),
		]));
	}

	#[test]
	fn insert_big_value() {
		let big_value0 = b"00000000000000000000000000000000";
		let big_value1 = b"11111111111111111111111111111111";

		let mut memdb = MemoryDB::new();
		let mut root = H256::new();
		let mut t = TrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], big_value0).unwrap();
		t.insert(&[0x11u8, 0x23], big_value1).unwrap();
		assert_eq!(*t.root(), trie_root(vec![
			(vec![0x01u8, 0x23], big_value0.to_vec()),
			(vec![0x11u8, 0x23], big_value1.to_vec())
		]));
	}

	#[test]
	fn insert_duplicate_value() {
		let big_value = b"00000000000000000000000000000000";

		let mut memdb = MemoryDB::new();
		let mut root = H256::new();
		let mut t = TrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], big_value).unwrap();
		t.insert(&[0x11u8, 0x23], big_value).unwrap();
		assert_eq!(*t.root(), trie_root(vec![
			(vec![0x01u8, 0x23], big_value.to_vec()),
			(vec![0x11u8, 0x23], big_value.to_vec())
		]));
	}

	#[test]
	fn test_at_empty() {
		let mut memdb = MemoryDB::new();
		let mut root = H256::new();
		let t = TrieDBMut::new(&mut memdb, &mut root);
		assert_eq!(t.get(&[0x5]), Ok(None));
	}

	#[test]
	fn test_at_one() {
		::ethcore_logger::init_log();
		let mut memdb = MemoryDB::new();
		let mut root = H256::new();
		let mut t = TrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		assert_eq!(t.get(&[0x1, 0x23]).unwrap().unwrap(), DBValue::from_slice(&[0x1u8, 0x23]));
		t.commit();
		trace!(target: "trie", "GET {:?}", t.get(&[0x1, 0x23]).unwrap().unwrap());
		assert_eq!(t.get(&[0x1, 0x23]).unwrap().unwrap(), DBValue::from_slice(&[0x1u8, 0x23]));
	}

	#[test]
	fn test_at_three() {
		let mut memdb = MemoryDB::new();
		let mut root = H256::new();
		let mut t = TrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		t.insert(&[0xf1u8, 0x23], &[0xf1u8, 0x23]).unwrap();
		t.insert(&[0x81u8, 0x23], &[0x81u8, 0x23]).unwrap();
		assert_eq!(t.get(&[0x01, 0x23]).unwrap().unwrap(), DBValue::from_slice(&[0x01u8, 0x23]));
		assert_eq!(t.get(&[0xf1, 0x23]).unwrap().unwrap(), DBValue::from_slice(&[0xf1u8, 0x23]));
		assert_eq!(t.get(&[0x81, 0x23]).unwrap().unwrap(), DBValue::from_slice(&[0x81u8, 0x23]));
		assert_eq!(t.get(&[0x82, 0x23]), Ok(None));
		t.commit();
		assert_eq!(t.get(&[0x01, 0x23]).unwrap().unwrap(), DBValue::from_slice(&[0x01u8, 0x23]));
		assert_eq!(t.get(&[0xf1, 0x23]).unwrap().unwrap(), DBValue::from_slice(&[0xf1u8, 0x23]));
		assert_eq!(t.get(&[0x81, 0x23]).unwrap().unwrap(), DBValue::from_slice(&[0x81u8, 0x23]));
		assert_eq!(t.get(&[0x82, 0x23]), Ok(None));
	}

	#[test]
	fn stress() {
		::ethcore_logger::init_log();
		let mut key = H256::new();
		let mut keys = Vec::new();
		let mut memdb = MemoryDB::new();
		let mut root = H256::new();

		for i in 0..10000 {
			key = keccak(&key);
			let mut value: [u8; 64] = [0u8; 64];
			&mut value[..32].copy_from_slice(&key);
			&mut value[32..].copy_from_slice(&key);
			keys.push((key, DBValue::from_slice(&value[0..i%63 + 1])));
		}

		{
			let mut t = TrieDBMut::new(&mut memdb, &mut root);
			for &(ref k, ref v) in keys.iter() {
				t.insert(k, v).unwrap();
			}
			for &(ref k, ref v) in keys.iter() {
				assert_eq!(t.get(&k).unwrap().unwrap(), *v);
			}
			t.commit();
		}

		{
			let t = TrieDBMut::from_existing(&mut memdb, &mut root).unwrap();
			for &(ref k, ref v) in keys.iter() {
				assert_eq!(t.get(k).unwrap().unwrap(), *v);
			}
		}
	}

	#[test]
	fn test_trie_existing() {
		let mut root = H256::new();
		let mut db = MemoryDB::new();
		{
			let mut t = TrieDBMut::new(&mut db, &mut root);
			t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		}

		{
			let _ = TrieDBMut::from_existing(&mut db, &mut root);
		}
	}

	#[test]
	fn insert_empty() {
		let mut seed = H256::new();
		let x = StandardMap {
				alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
				min_key: 5,
				journal_key: 0,
				value_mode: ValueMode::Index,
				count: 4,
		}.make_with(&mut seed);

		let mut db = MemoryDB::new();
		let mut root = H256::new();
		let mut t = TrieDBMut::new(&mut db, &mut root);
		for &(ref key, ref value) in &x {
			t.insert(key, value).unwrap();
		}

		assert_eq!(*t.root(), trie_root(x.clone()));

		for &(ref key, _) in &x {
			t.insert(key, &[]).unwrap();
		}

		assert!(t.is_empty());
		assert_eq!(*t.root(), KECCAK_NULL_RLP);
	}

	#[test]
	fn return_old_values() {
		let mut seed = H256::new();
		let x = StandardMap {
				alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
				min_key: 5,
				journal_key: 0,
				value_mode: ValueMode::Index,
				count: 4,
		}.make_with(&mut seed);

		let mut db = MemoryDB::new();
		let mut root = H256::new();
		let mut t = TrieDBMut::new(&mut db, &mut root);
		for &(ref key, ref value) in &x {
			assert!(t.insert(key, value).unwrap().is_none());
			assert_eq!(t.insert(key, value).unwrap(), Some(DBValue::from_slice(value)));
		}

		for (key, value) in x {
			assert_eq!(t.remove(&key).unwrap(), Some(DBValue::from_slice(&value)));
			assert!(t.remove(&key).unwrap().is_none());
		}
	}
}

