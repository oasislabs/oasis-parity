#![feature(wasi_ext)]

use std::io::{Read as _, Write as _};
use std::os::wasi::prelude::FromRawFd;

#[link(wasm_import_module = "wasi_unstable")]
#[allow(improper_ctypes)]
extern "C" {
	#[link_name = "blockchain_transact"]
	fn __wasi_blockchain_transact(
		callee_addr: *const u8,
		value: *const u128,
		input: *const u8,
		input_len: u64,
		fd: *mut libc::__wasi_fd_t,
	) -> libc::__wasi_errno_t;
}

const ADDRESS_LEN: usize = 20;

fn main() {
	let mut callee = Vec::with_capacity(ADDRESS_LEN);
	std::io::stdin().read_to_end(&mut callee).unwrap();

	let value = 42u128;
	let input = b"hello, other service!";
	let mut fd = Default::default();
	assert_eq!(
		unsafe {
			__wasi_blockchain_transact(
				callee.as_ptr(),
				&value as *const u128,
				input.as_ptr(),
				input.len() as u64,
				&mut fd as *mut _,
			)
		},
		libc::__WASI_ESUCCESS
	);
	let mut f_out = unsafe { std::fs::File::from_raw_fd(fd) };
	let mut output = Vec::new();
	f_out.read_to_end(&mut output).unwrap();
	std::io::stdout().write_all(&output).unwrap();
}
