// (c) Oasis Labs.  All right reserved.

use ethereum_types::{H256, Address};

use trace_ext::ext_tracer::ExtTracer;

/// No-op externalities tracer.
pub struct NoopExtTracer;

impl ExtTracer for NoopExtTracer {
    fn trace_storage_at(&self, _key: &H256) {
    }

    /// Transaction execution writes into persistent state.
    fn trace_set_storage(&self, _key: &H256) {
    }

    /// Transaction performs an exists query.
    fn trace_exists(&self, _address: &Address) {
    }

    /// Transactions performs an exists_and_not_null query.
    fn trace_exists_and_not_null(&self, _address: &Address) {
    }

    /// Transaction performs an origin_balance or balance query.  Unlike Ext, we do not know
    /// origin address, so it must be provided by Ext implementations.
    fn trace_balance(&self, _origin_address: &Address) {
    }

    /// subtracer returns an Ext tracer for use for the context of the sub-transaction call.
    fn subtracer(&mut self, _code_address: &Address) -> Self {
        return NoopExtTracer{}
    }
}
