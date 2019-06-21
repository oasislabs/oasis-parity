
#![feature(test)]
extern crate test;

use super::*;
use self::test::Bencher;

use std::sync::Arc;
use std::collections::HashMap;
use byteorder::{LittleEndian, ByteOrder};
use ethereum_types::{H256, U256, Address};

use super::WasmRuntime;
use vm::{self, Vm, GasLeft, ActionParams, ActionValue};
use vm::tests::{FakeCall, FakeExt, FakeCallType};

macro_rules! load_sample {
    ($name: expr) => {
        include_bytes!(concat!("../../res/wasm-tests/compiled/", $name)).to_vec()
    }
}

fn wasm_runtime() -> WasmRuntime {
    WasmRuntime
}

fn prepare_module(params: ActionParams, ext: &mut vm::Ext) -> wasmer_runtime::Instance {
 
    let adjusted_gas = params.gas * U256::from(ext.schedule().wasm().opcodes_div) /
			U256::from(ext.schedule().wasm().opcodes_mul);

    // Explicitly split the input into code and data
    let (_module, code, data) = parser::payload(&params, ext.schedule().wasm()).unwrap();

    let mut runtime = Runtime::with_params(
        ext,
        adjusted_gas.low_u64(), // cannot overflow, checked above
        data.to_vec(),
        RuntimeContext {
            address: params.address,
            sender: params.sender,
            origin: params.origin,
            value: params.value.value(),
        },
    );

    let raw_ptr = &mut runtime as *mut _ as *mut c_void;
        
    // TODO: This line causes a lot of log output, find a way to limit to log level WARN
    let module = wasmer_runtime::compile(&code).unwrap();
        
    // Default memory descriptor
    let mut descriptor = wasmer_runtime::wasm::MemoryDescriptor {
        minimum: wasmer_runtime::units::Pages(0),
        maximum: Some(wasmer_runtime::units::Pages(0)),
        shared: false,
    };

    // Get memory descriptor from code import
    // TODO handle case if more than 1 present
    for (_index, (_import_object, expected_memory_desc)) in &module.info().imported_memories {
        descriptor = *expected_memory_desc;
    }

    let mem_obj = memory::Memory::new(descriptor).unwrap();
    let mem_view: MemoryView<u8> = mem_obj.view();
    let memory_size = mem_view.len() / 65535;
    module.instantiate(&runtime::imports::get_import_object(mem_obj, raw_ptr)).unwrap()

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

    let instance = prepare_module(params, &mut ext);

    b.iter(|| {
        instance.call("call", &[]);
    });
}

#[bench]
fn bench_storage_read(b: &mut Bencher) {

	let code = load_sample!("storage_read.wasm");
	let address: Address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6".parse().unwrap();
    let mut ext = FakeExt::new().with_wasm();
	ext.store.insert("0100000000000000000000000000000000000000000000000000000000000000".into(), address.into());

    let mut params = ActionParams::default();
    params.gas = U256::from(100_000);
    params.code = Some(Arc::new(code.clone()));
    let instance = prepare_module(params, &mut ext);

    b.iter(|| {
        instance.call("call", &[]);
    });
}

