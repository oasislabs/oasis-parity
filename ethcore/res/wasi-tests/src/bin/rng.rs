fn main() {
	let mut map = std::collections::HashMap::<String, String>::new();
	map.insert("hello".to_string(), "world!".to_string());
	assert_eq!(map.get("hello").map(|s| s.as_str()), Some("world!"));
}
