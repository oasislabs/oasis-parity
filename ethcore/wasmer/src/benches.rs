#![feature(test)]
extern crate test;

use self::test::Bencher;
use super::*;

use byteorder::{ByteOrder, LittleEndian};
use ethereum_types::{Address, H256, U256};
use std::collections::HashMap;
use std::sync::Arc;

use super::WasmRuntime;
use vm::tests::{FakeCall, FakeCallType, FakeExt};
use vm::{self, ActionParams, ActionValue, GasLeft, Vm};

macro_rules! load_sample {
	($name: expr) => {
		include_bytes!(concat!("../../res/wasm-tests/compiled/", $name)).to_vec()
	};
}

fn wasm_runtime() -> WasmRuntime {
	WasmRuntime { module: None }
}

#[bench]
fn bench_identity(b: &mut Bencher) {
	let sender: Address = "01030507090b0d0f11131517191b1d1f21232527".parse().unwrap();
	let mut ext = FakeExt::new().with_wasm();

	let code = load_sample!("identity.wasm");
	let mut params = ActionParams::default();
	params.sender = sender.clone();
	params.gas = U256::from(100_000);
	params.code = Some(Arc::new(code.clone()));

	let mut runtime = wasm_runtime();
	runtime.prepare(&params, &mut ext);

	b.iter(|| {
		let result = runtime.exec(params.clone(), &mut ext);
	});
}

#[bench]
fn bench_storage_read(b: &mut Bencher) {
	let code = load_sample!("storage_read.wasm");
	let address: Address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6".parse().unwrap();
	let mut ext = FakeExt::new().with_wasm();
	ext.store.insert(
		"0100000000000000000000000000000000000000000000000000000000000000".into(),
		address.into(),
	);

	let mut params = ActionParams::default();
	params.gas = U256::from(100_000);
	params.code = Some(Arc::new(code.clone()));

	let mut runtime = wasm_runtime();
	runtime.prepare(&params, &mut ext);

	b.iter(|| {
		let result = runtime.exec(params.clone(), &mut ext);
	});
}
