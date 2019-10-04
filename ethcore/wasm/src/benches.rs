#![feature(test)]
extern crate test;

use self::test::Bencher;
use super::*;


use ethereum_types::{Address, U256};

use std::sync::Arc;

use super::WasmInterpreter;
use vm::tests::{FakeExt};
use vm::{self, ActionParams, ActionValue, Vm};

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

fn wasm_interpreter() -> WasmInterpreter {
	WasmInterpreter
}

/// Do everything but the contract call itself, used for testing microbenchmarks
fn prepare_module(params: ActionParams, ext: &mut dyn vm::Ext) -> (Runtime, wasmi::ModuleRef) {
	let is_create = ext.is_create();

	let parser::ParsedModule {
		module, data, ..
	} = parser::payload(
		&params,
		ext.schedule().wasm(),
		if is_create {
			Some(subst_main_call)
		} else {
			None
		},
	)
	.unwrap();

	let loaded_module = wasmi::Module::from_parity_wasm_module(module)
		.map_err(Error::Interpreter)
		.unwrap();

	let instantiation_resolver = env::ImportResolver::with_limit(<u32>::max_value() - 1);

	let module_instance = wasmi::ModuleInstance::new(
		&loaded_module,
		&wasmi::ImportsBuilder::new()
			.with_resolver("env", &instantiation_resolver)
			.with_resolver("wasi_unstable", &instantiation_resolver),
	)
	.map_err(Error::Interpreter)
	.unwrap();

	let adjusted_gas = params.gas * U256::from(ext.schedule().wasm().opcodes_div)
		/ U256::from(ext.schedule().wasm().opcodes_mul);

	let _initial_memory = instantiation_resolver
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
			value_str: params.value.value().as_u64().to_string(),
			aad_str: params.aad.as_ref().map(base64::encode).unwrap_or_default(),
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
	let code = load_sample!("empty");
	let address: Address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6".parse().unwrap();

	let mut params = ActionParams::default();
	params.address = address.clone();
	params.gas = U256::from(100_000);
	params.code = Some(Arc::new(code));

	let mut ext = FakeExt::new().with_wasm();
	let (mut runtime, module_instance) = prepare_module(params, &mut ext);

	b.iter(|| {
		module_instance.invoke_export("_start", &[], &mut runtime);
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

	let mut interpreter = wasm_interpreter();

	b.iter(|| interpreter.exec(params.clone(), &mut ext));
}

#[bench]
fn bench_event(b: &mut Bencher) {
	let code = load_sample!("event");
	let mut params = ActionParams::default();
	params.gas = U256::from(1_000_000);
	params.value = ActionValue::Transfer(0.into());
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();

	let mut interpreter = wasm_interpreter();
	b.iter(|| interpreter.exec(params.clone(), &mut ext));
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

	let mut interpreter = wasm_interpreter();

	b.iter(|| interpreter.exec(params.clone(), &mut ext));
}

#[bench]
fn bench_factorial(b: &mut Bencher) {
	let code = load_sample!("factorial");
	let mut params = ActionParams::default();
	params.data = Some(b"20".to_vec());
	params.gas = U256::from(1_000_000);
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();

	let mut interpreter = wasm_interpreter();

	b.iter(|| interpreter.exec(params.clone(), &mut ext));
}

#[bench]
fn bench_fib(b: &mut Bencher) {
	let code = load_sample!("fibonacci");
	let mut params = ActionParams::default();
	params.data = Some(b"5".to_vec());
	params.gas = U256::from(1_000_000);
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();

	let mut interpreter = wasm_interpreter();

	b.iter(|| interpreter.exec(params.clone(), &mut ext));
}
