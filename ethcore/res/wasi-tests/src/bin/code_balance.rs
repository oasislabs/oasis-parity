use std::{fs, path::PathBuf};

fn main() {
	fs::write("the_code", fs::read("bytecode").expect("no code")).unwrap();

	let mut balance_path = PathBuf::from("/opt/oasis");
	balance_path.push(std::env::var("ADDRESS").unwrap());
	balance_path.push("balance");
	fs::write("the_balance", fs::read(balance_path).unwrap()).unwrap();
}
