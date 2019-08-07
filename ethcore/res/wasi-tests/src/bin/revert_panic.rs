fn main() {
	std::fs::write("the_deets", "incriminating evidence").unwrap();
	panic!("eek!");
}
