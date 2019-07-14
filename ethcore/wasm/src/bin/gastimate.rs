use std::sync::Arc;

use ethereum_types::{Address, U256};
use vm::{tests::FakeExt, ActionParams, GasLeft, Vm as _};
use wasm::WasmInterpreter;

const INIT_GAS: u64 = 5_000_000;
const NUM_TRIALS: usize = 10;

fn main() {
	let code = Arc::new(std::fs::read(std::env::args().nth(1).unwrap()).unwrap());

	let gases_used = (0..NUM_TRIALS)
		.map(|_| {
			let mut ext = FakeExt::new().with_wasm();
			let mut params = ActionParams::default();
			params.gas = U256::from(INIT_GAS);
			params.code = Some(Arc::clone(&code));

			let gas_used = match WasmInterpreter.exec(params, &mut ext).unwrap() {
				GasLeft::Known(gas_left) => gas_left,
				GasLeft::NeedsReturn { gas_left, .. } => gas_left,
			};

			(INIT_GAS - gas_used.low_u64()) as f64
		})
		.collect::<Vec<f64>>();

	let avg_gas_used = gases_used.iter().sum::<f64>() / (gases_used.len() as f64);
	let gas_used_std = gases_used
		.into_iter()
		.map(|g| (g - avg_gas_used).powf(2.0))
		.sum::<f64>()
		.sqrt();

	println!("{:.1} ({:.1})", avg_gas_used, gas_used_std);
}
