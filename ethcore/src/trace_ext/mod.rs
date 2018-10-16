// (c) Oasis Labs.  All right reserved.

/// ExtTracer trait for tracing Ext (Externalities) calls. 
pub mod ext_tracer;
/// Concrete class for no-op tracing.
pub mod noop;
pub use self::ext_tracer::ExtTracer;
pub use self::noop::NoopExtTracer;
