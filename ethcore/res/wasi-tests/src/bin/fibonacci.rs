use std::io::Read as _;

fn main() {
	let mut input = Vec::with_capacity(16);
	std::io::stdin().read_to_end(&mut input).unwrap();
	let input_u64 = std::str::from_utf8(&input).unwrap().parse::<u64>().unwrap();
	println!("the output is: {}", fib(input_u64));
}

fn fib(n: u64) -> u64 {
    match n {
        0 => 1,
        1 => 1,
        n => fib(n - 1) + fib(n - 2),
    }
}