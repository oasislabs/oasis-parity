#[no_mangle]
unsafe extern "C" fn _oasis_deploy() {
	std::fs::write("message", "hello").expect("no file");
}

fn main() {
	println!(
		"ctor says {}",
		std::str::from_utf8(&std::fs::read("message").unwrap()).unwrap()
	);
}
