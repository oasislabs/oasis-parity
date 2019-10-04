use std::io::Write as _;

fn main() {
	let mut log_f = std::fs::OpenOptions::new()
		.append(true)
		.open("/opt/oasis/log")
		.expect("No log sock");
	// write topics
	let num_topics = 3;
	log_f.write(&(num_topics as u32).to_le_bytes()).unwrap();
	let topic_lengths_start = 4;
	(topic_lengths_start..(topic_lengths_start + num_topics)).for_each(|i| {
		log_f.write(&(i as u32).to_le_bytes()).unwrap();
		log_f.write(&vec![i as u8; i]).unwrap();
	});
	let data = b"hello, world!";
	log_f.write(&(data.len() as u32).to_le_bytes()).unwrap();
	log_f.write(data).unwrap();
	log_f.flush().unwrap();
}
