use std::io::Read as _;

fn main() {
	let mut input = Vec::with_capacity(16);
	std::io::stdin().read_to_end(&mut input).unwrap();
	println!("the input was: {}", std::str::from_utf8(&input).unwrap());
	let aad = std::env::var("AAD").unwrap();
	if !aad.is_empty() {
		println!(
			"the aad was: {}",
			String::from_utf8(base64::decode(&std::env::var("AAD").unwrap()).unwrap()).unwrap()
		);
	}
}
