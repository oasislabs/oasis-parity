// (c) Oasis Labs.  All right reserved.

use ethereum_types::{H256, Address};

/// Interface used to trace activities at the Ext interface.  This essentially mirrors the Ext
/// interface, except no results are returned.
pub trait ExtTracer: Send {
	/// Transaction execution reads from persistent state.
	fn trace_storage_at(&self, key: &H256);

	/// Transaction execution writes into persistent state.
	fn trace_set_storage(&self, key: &H256);

	/// Transaction performs an exists query.
	fn trace_exists(&self, address: &Address);

	/// Transactions performs an exists_and_not_null query.
	fn trace_exists_and_not_null(&self, address: &Address);

	/// Transaction performs an origin_balance or balance query.  Unlike Ext, we do not know
	/// origin address, so it must be provided by Ext implementations.
	fn trace_balance(&self, origin_address: &Address);

	// The rest of the Ext trait functions are not persistent state related.

	/// Returns an Ext tracer for use for the context of the sub-transaction call.
	fn subtracer(&mut self, code_address: &Address) -> Self;
}
