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
use wasmer_runtime;

macro_rules! load_sample {
	($name: expr) => {{
		ethcore_logger::init_log();
		include_bytes!(concat!(
			"../../res/wasi-tests/target/service/",
			$name,
			".wasm"
			))
		.to_vec()
		}};
}

fn wasm_runtime() -> WasmRuntime {
	WasmRuntime::default()
}

/// Do everything but the contract call itself, used for testing microbenchmarks
fn prepare_module(params: ActionParams, ext: &mut vm::Ext) -> wasmer_runtime_core::Instance {
	let (_, code, data) = parser::payload(&params, ext.schedule().wasm()).unwrap();

	let module = wasmer_runtime::compile(&code).unwrap();

	let adjusted_gas_limit = params.gas * U256::from(ext.schedule().wasm().opcodes_div)
		/ U256::from(ext.schedule().wasm().opcodes_mul);

	let mut runtime = Runtime::with_params(
		ext,
		adjusted_gas_limit.low_u64(), // cannot overflow, checked above
		data.to_vec(),
		RuntimeContext {
			address: params.address,
			sender: params.sender,
			origin: params.origin,
			code_address: params.code_address,
			value: params.value.value(),
			value_str: params.value.value().as_u64().to_string(),
		},
	);

	// Default memory descriptor
	let mut descriptor = wasmer_runtime_core::types::MemoryDescriptor {
		minimum: wasmer_runtime_core::units::Pages(0),
		maximum: Some(wasmer_runtime_core::units::Pages(0)),
		shared: false,
	};

	// Get memory descriptor from code import
	// TODO handle case if more than 1 present
	for (_, (_, expected_memory_desc)) in &module.info().imported_memories {
		descriptor = *expected_memory_desc;
	}

	let mem_obj = memory::Memory::new(descriptor).unwrap();
	let memory_view: MemoryView<u8> = mem_obj.view();
	let memory_size = memory_view.len() / 65535;

	let raw_ptr = &mut runtime as *mut _ as *mut c_void;
	let import_object = runtime::imports::get_import_object(mem_obj, raw_ptr);

	// Create the wasmer runtime instance to call function
	module.instantiate(&import_object).unwrap()
}

#[bench]
fn microbench_empty(b: &mut Bencher) {
	let code = load_sample!("empty");
	let address: Address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6".parse().unwrap();

	let mut params = ActionParams::default();
	params.address = address.clone();
	params.gas = U256::from(100_000);
	params.code = Some(Arc::new(code));

	let mut ext = FakeExt::new().with_wasm();
	let module_instance = prepare_module(params, &mut ext);

	b.iter(|| {
		module_instance.call("_start", &[]);
	});
}

#[bench]
fn bench_empty(b: &mut Bencher) {
	let code = load_sample!("empty");
	let address: Address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6".parse().unwrap();

	let mut params = ActionParams::default();
	params.address = address.clone();
	params.gas = U256::from(100_000);
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();

	let mut runtime = wasm_runtime();
	runtime.prepare(&params, &mut ext);

	b.iter(|| runtime.exec(params.clone(), &mut ext));
}

#[bench]
fn bench_event(b: &mut Bencher) {
	let code = load_sample!("event");
	let mut params = ActionParams::default();
	params.gas = U256::from(1_000_000);
	params.value = ActionValue::Transfer(0.into());
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();

	let mut runtime = wasm_runtime();
	runtime.prepare(&params, &mut ext).unwrap();

	b.iter(|| runtime.exec(params.clone(), &mut ext));
}

#[bench]
fn bench_read_delete(b: &mut Bencher) {
	let code = load_sample!("read_delete");
	let mut params = ActionParams::default();
	params.gas = U256::from(1_000_000);
	params.value = ActionValue::Transfer(0.into());
	params.code = Some(Arc::new(code));

	let mut ext = FakeExt::new().with_wasm();
	let key = b"value".to_vec();
	let val_str = "the_value";
	ext.store.insert(key.clone(), val_str.as_bytes().to_vec());

	let mut runtime = wasm_runtime();
	runtime.prepare(&params, &mut ext).unwrap();

	b.iter(|| runtime.exec(params.clone(), &mut ext));
}

#[bench]
fn bench_factorial(b: &mut Bencher) {
	let code = load_sample!("factorial");
	let mut params = ActionParams::default();
	params.data = Some(b"20".to_vec());
	params.gas = U256::from(1_000_000);
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();

	let mut runtime = wasm_runtime();
	runtime.prepare(&params, &mut ext).unwrap();

	b.iter(|| runtime.exec(params.clone(), &mut ext));
}

#[bench]
fn bench_fib(b: &mut Bencher) {
	let code = load_sample!("fibonacci");
	let mut params = ActionParams::default();
	params.data = Some(b"5".to_vec());
	params.gas = U256::from(1_000_000);
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();

	let mut runtime = wasm_runtime();
	runtime.prepare(&params, &mut ext).unwrap();

	b.iter(|| runtime.exec(params.clone(), &mut ext));
}
