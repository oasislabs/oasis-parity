use std::io::Write as _;

fn main() {
	std::io::stdout()
		.write_all(&std::fs::read("value").unwrap())
		.unwrap();
	std::fs::remove_file("value").unwrap();
	std::process::exit(0);
}
