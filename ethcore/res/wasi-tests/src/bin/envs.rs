fn main() {
	std::fs::write("address", std::env::var("ADDRESS").expect("No address.")).unwrap();
	std::fs::write("sender", std::env::var("SENDER").expect("No sender")).unwrap();
	std::fs::write("value", std::env::var("VALUE").expect("No value")).unwrap();
}
