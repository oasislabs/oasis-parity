#![feature(wasi_ext)]

use std::io::{Read as _, Write as _};
use std::os::wasi::prelude::FromRawFd;

#[link(wasm_import_module = "wasi_unstable")]
#[allow(improper_ctypes)]
extern "C" {
	#[link_name = "blockchain_create"]
	fn __wasi_blockchain_create(
		value: *const u128,
		code: *const u8,
		code_len: u64,
		fd: *mut libc::__wasi_fd_t,
	) -> libc::__wasi_errno_t;
}

fn main() {
	let value = 42u128;
	let code = include_bytes!("../../target/service/create_ctor.wasm");
	let mut fd = Default::default();
	assert_eq!(
		unsafe {
			__wasi_blockchain_create(
				&value as *const u128,
				code.as_ptr(),
				code.len() as u64,
				&mut fd as *mut _,
			)
		},
		libc::__WASI_ESUCCESS
	);
	let mut f_out = unsafe { std::fs::File::from_raw_fd(fd) };
	let mut new_addr_bytes = Vec::new();
	f_out.read_to_end(&mut new_addr_bytes).unwrap();
	std::io::stdout().write_all(&new_addr_bytes).unwrap();
}
