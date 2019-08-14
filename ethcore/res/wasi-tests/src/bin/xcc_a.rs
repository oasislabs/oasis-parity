use std::io::Read as _;

#[link(wasm_import_module = "wasi_unstable")]
extern "C" {
	#[link_name = "blockchain_transact"]
	fn __wasi_blockchain_transact(
		callee_addr: *const u8,
		value: u64,
		input: *const u8,
		input_len: u64,
		fd: *mut libc::__wasi_fd_t,
	) -> libc::__wasi_errno_t;
}

const ADDRESS_LEN: usize = 20;

fn main() {
	let mut callee = Vec::with_capacity(ADDRESS_LEN);
	std::io::stdin().read_to_end(&mut callee).unwrap();

	let value = 42;
	let input = b"hello, other service!";
	let mut fd = Default::default();
	assert_eq!(
		unsafe {
			__wasi_blockchain_transact(
				callee.as_ptr(),
				value,
				input.as_ptr(),
				input.len() as u64,
				&mut fd as *mut _,
			)
		},
		libc::__WASI_ESUCCESS
	);
}
