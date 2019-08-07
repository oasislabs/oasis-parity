use std::io::Read as _;

fn main() {
	let mut input = Vec::with_capacity(16);
	std::io::stdin().read_to_end(&mut input).unwrap();
	println!("the input was: {}", std::str::from_utf8(&input).unwrap());
}
