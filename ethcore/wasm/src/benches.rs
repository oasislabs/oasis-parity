
#![feature(test)]
extern crate test;

use super::*;
use self::test::Bencher;

use std::sync::Arc;
use std::collections::HashMap;
use byteorder::{LittleEndian, ByteOrder};
use ethereum_types::{H256, U256, Address};

use super::WasmInterpreter;
use vm::{self, Vm, GasLeft, ActionParams, ActionValue};
use vm::tests::{FakeCall, FakeExt, FakeCallType};

macro_rules! load_sample {
    ($name: expr) => {
        include_bytes!(concat!("../../res/wasm-tests/compiled/", $name)).to_vec()
    }
}

fn wasm_interpreter() -> WasmInterpreter {
    WasmInterpreter
}

fn prepare_module(params: ActionParams, ext: &mut vm::Ext) -> (Runtime, wasmi::ModuleRef) {
    let (module, data) = parser::payload(&params, ext.schedule().wasm()).unwrap();

    let loaded_module = wasmi::Module::from_parity_wasm_module(module).map_err(Error::Interpreter).unwrap();

    let instantiation_resolver = env::ImportResolver::with_limit(<u32>::max_value() - 1);

    let module_instance = wasmi::ModuleInstance::new(
        &loaded_module,
        &wasmi::ImportsBuilder::new().with_resolver("env", &instantiation_resolver)
    ).map_err(Error::Interpreter).unwrap();

    let adjusted_gas = params.gas * U256::from(ext.schedule().wasm().opcodes_div) /
        U256::from(ext.schedule().wasm().opcodes_mul);

    let initial_memory = instantiation_resolver.memory_size().map_err(Error::Interpreter).unwrap();

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

    let module_ref = module_instance.run_start(&mut runtime).map_err(Error::Trap).unwrap();
    (runtime, module_ref)
}

#[bench]
fn bench_identity(b: &mut Bencher) {
    ethcore_logger::init_log();

    let sender: Address = "01030507090b0d0f11131517191b1d1f21232527".parse().unwrap();
    let mut ext = FakeExt::new().with_wasm();
    let mut interpreter = wasm_interpreter();
    let code = load_sample!("identity.wasm");

    let mut params = ActionParams::default();
    params.sender = sender.clone();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code.clone()));
    let (mut runtime, module_instance) = prepare_module(params, &mut ext);

    b.iter(|| {
        module_instance.invoke_export("call", &[], &mut runtime);
    });
}

#[bench]
fn bench_storage_read(b: &mut Bencher) {
	ethcore_logger::init_log();

	let code = load_sample!("storage_read.wasm");
	let address: Address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6".parse().unwrap();
	let mut interpreter = wasm_interpreter();
    let mut ext = FakeExt::new().with_wasm();
	ext.store.insert("0100000000000000000000000000000000000000000000000000000000000000".into(), address.into());

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code.clone()));
    let (mut runtime, module_instance) = prepare_module(params, &mut ext);

    b.iter(|| {    
        module_instance.invoke_export("call", &[], &mut runtime);
    });
}

