#![feature(test)]
extern crate test;

use self::test::Bencher;
use super::*;

use byteorder::{ByteOrder, LittleEndian};
use ethereum_types::{Address, H256, U256};
use std::collections::HashMap;
use std::sync::Arc;

use super::WasmInterpreter;
use vm::tests::{FakeCall, FakeCallType, FakeExt};
use vm::{self, ActionParams, ActionValue, GasLeft, Vm};

macro_rules! load_sample {
	($name: expr) => {
		include_bytes!(concat!("../../res/wasm-tests/compiled/", $name)).to_vec()
	};
}

fn wasm_interpreter() -> WasmInterpreter {
	WasmInterpreter
}

/// Do everything but the contract call itself, used for testing microbenchmarks
fn prepare_module(params: ActionParams, ext: &mut vm::Ext) -> (Runtime, wasmi::ModuleRef) {
	let (module, data) = parser::payload(&params, ext.schedule().wasm()).unwrap();

	let loaded_module = wasmi::Module::from_parity_wasm_module(module)
		.map_err(Error::Interpreter)
		.unwrap();

	let instantiation_resolver = env::ImportResolver::with_limit(<u32>::max_value() - 1);

	let module_instance = wasmi::ModuleInstance::new(
		&loaded_module,
		&wasmi::ImportsBuilder::new().with_resolver("env", &instantiation_resolver),
	)
	.map_err(Error::Interpreter)
	.unwrap();

	let adjusted_gas = params.gas * U256::from(ext.schedule().wasm().opcodes_div)
		/ U256::from(ext.schedule().wasm().opcodes_mul);

	let initial_memory = instantiation_resolver
		.memory_size()
		.map_err(Error::Interpreter)
		.unwrap();

	let mut runtime = Runtime::with_params(
		ext,
		instantiation_resolver.memory_ref(),
		// cannot overflow, checked above
		adjusted_gas.low_u64(),
		data.to_vec(),
		RuntimeContext {
			address: params.address,
			sender: params.sender,
			origin: params.origin,
			code_address: params.code_address,
			value: params.value.value(),
		},
	);

	let module_ref = module_instance
		.run_start(&mut runtime)
		.map_err(Error::Trap)
		.unwrap();
	(runtime, module_ref)
}

#[bench]
fn microbench_empty(b: &mut Bencher) {
	let code = load_sample!("empty.wasm");
	let address: Address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6".parse().unwrap();

	let mut params = ActionParams::default();
	params.address = address.clone();
	params.gas = U256::from(100_000);
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();

	let (mut runtime, module_instance) = prepare_module(params, &mut ext);

	b.iter(|| {
		module_instance.invoke_export("call", &[], &mut runtime);
	});
}

#[bench]
fn microbench_create(b: &mut Bencher) {
	let mut params = ActionParams::default();
	params.gas = U256::from(100_000);
	params.code = Some(Arc::new(load_sample!("creator.wasm")));
	params.data = Some(vec![0u8, 2, 4, 8, 16, 32, 64, 128]);
	params.value = ActionValue::transfer(1_000_000_000);

	let mut ext = FakeExt::new().with_wasm();
	let (mut runtime, module_instance) = prepare_module(params, &mut ext);

	b.iter(|| {
		module_instance.invoke_export("call", &[], &mut runtime);
	});
}

#[bench]
fn microbench_alloc(b: &mut Bencher) {
	let code = load_sample!("alloc.wasm");

	let mut params = ActionParams::default();
	params.gas = U256::from(10_000_000);
	params.code = Some(Arc::new(code));
	params.data = Some(vec![0u8]);
	let mut ext = FakeExt::new().with_wasm();

	let (mut runtime, module_instance) = prepare_module(params, &mut ext);

	b.iter(|| {
		module_instance.invoke_export("call", &[], &mut runtime);
	});
}

#[bench]
fn microbench_storage_read(b: &mut Bencher) {
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

	let (mut runtime, module_instance) = prepare_module(params, &mut ext);

	b.iter(|| {
		module_instance.invoke_export("call", &[], &mut runtime);
	});
}

#[bench]
fn microbench_keccak(b: &mut Bencher) {
	let code = load_sample!("keccak.wasm");

	let mut params = ActionParams::default();
	params.gas = U256::from(100_000);
	params.code = Some(Arc::new(code));
	params.data = Some(b"something".to_vec());
	let mut ext = FakeExt::new().with_wasm();

	let (mut runtime, module_instance) = prepare_module(params, &mut ext);

	b.iter(|| {
		module_instance.invoke_export("call", &[], &mut runtime);
	});
}

#[bench]
fn bench_empty(b: &mut Bencher) {
	let code = load_sample!("empty.wasm");
	let address: Address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6".parse().unwrap();

	let mut params = ActionParams::default();
	params.address = address.clone();
	params.gas = U256::from(100_000);
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();

	let mut runtime = wasm_interpreter();
	runtime.prepare(&params, &mut ext);

	b.iter(|| runtime.exec(params.clone(), &mut ext));
}

#[bench]
fn bench_create(b: &mut Bencher) {
	let mut params = ActionParams::default();
	params.gas = U256::from(100_000);
	params.code = Some(Arc::new(load_sample!("creator.wasm")));
	params.data = Some(vec![0u8, 2, 4, 8, 16, 32, 64, 128]);
	params.value = ActionValue::transfer(1_000_000_000);

	let mut ext = FakeExt::new().with_wasm();

	let mut runtime = wasm_interpreter();
	runtime.prepare(&params, &mut ext);

	b.iter(|| runtime.exec(params.clone(), &mut ext));
}

#[bench]
fn bench_alloc(b: &mut Bencher) {
	let code = load_sample!("alloc.wasm");

	let mut params = ActionParams::default();
	params.gas = U256::from(10_000_000);
	params.code = Some(Arc::new(code));
	params.data = Some(vec![0u8]);
	let mut ext = FakeExt::new().with_wasm();

	let mut runtime = wasm_interpreter();
	runtime.prepare(&params, &mut ext);

	b.iter(|| runtime.exec(params.clone(), &mut ext));
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

	let mut runtime = wasm_interpreter();
	runtime.prepare(&params, &mut ext);

	b.iter(|| {
		runtime.exec(params.clone(), &mut ext);
	});
}

#[bench]
fn bench_keccak(b: &mut Bencher) {
	let code = load_sample!("keccak.wasm");

	let mut params = ActionParams::default();
	params.gas = U256::from(100_000);
	params.code = Some(Arc::new(code));
	params.data = Some(b"something".to_vec());
	let mut ext = FakeExt::new().with_wasm();

	let mut runtime = wasm_interpreter();
	runtime.prepare(&params, &mut ext);

	b.iter(|| {
		runtime.exec(params.clone(), &mut ext);
	});
}
