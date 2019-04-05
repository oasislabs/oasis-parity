//! Compatibility with libraries that use malloc.
//!
//! Note that this only exposes the required symbols to avoid linking errors
//! but these symbols should not actually be used.

#[no_mangle]
pub fn malloc() {
    unreachable!();
}

#[no_mangle]
pub fn free() {
    unreachable!();
}

#[no_mangle]
pub fn abort() {
    unreachable!();
}
