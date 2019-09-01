// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

use ethereum_types::{Address, U256};
use std::sync::Arc;

use vm::{self, tests::FakeExt, ActionParams, ActionValue, GasLeft, ReturnData, Vm};

use crate::WasmInterpreter;

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

fn test_finalize(res: Result<GasLeft, vm::Error>) -> Result<(u64, ReturnData, bool), vm::Error> {
	match res {
		Ok(GasLeft::Known(_)) => unreachable!("exec always returns NeedsReturn"),
		Ok(GasLeft::NeedsReturn {
			gas_left,
			data,
			apply_state,
		}) => Ok((gas_left.low_u64(), data, apply_state)),
		Err(e) => Err(e),
	}
}

fn wasm_interpreter() -> WasmInterpreter {
	WasmInterpreter
}

#[test]
fn empty() {
	let code = load_sample!("empty");
	let address: Address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6".parse().unwrap();

	let mut params = ActionParams::default();
	params.address = address.clone();
	params.gas = U256::from(100_000);
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();

	let mut interpreter = wasm_interpreter();
	let (_, _, apply_state) = test_finalize(interpreter.exec(params, &mut ext)).unwrap();
	assert!(apply_state);
}

#[test]
fn rng() {
	let code = load_sample!("rng");
	let address: Address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6".parse().unwrap();

	let mut params = ActionParams::default();
	params.address = address.clone();
	params.gas = U256::from(1_000_000);
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();

	let mut interpreter = wasm_interpreter();
	let (_, _, apply_state) = test_finalize(interpreter.exec(params, &mut ext)).unwrap();
	assert!(apply_state);
}

#[test]
fn gas_limit() {
	let code = load_sample!("empty");
	let address: Address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6".parse().unwrap();

	let mut params = ActionParams::default();
	params.address = address.clone();
	params.gas = U256::from(100);
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();

	let mut interpreter = wasm_interpreter();
	test_finalize(interpreter.exec(params, &mut ext)).unwrap_err();
}

#[test]
fn envs() {
	let code = load_sample!("envs");
	let address_str = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6";
	let sender_str = "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d";
	let address: Address = address_str.parse().unwrap();
	let sender: Address = sender_str.parse().unwrap();
	let value = 1_000_000_000u64;

	let mut params = ActionParams::default();
	params.address = address.clone();
	params.sender = sender.clone();
	params.gas = U256::from(1_000_000);
	params.value = ActionValue::transfer(value);
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();

	let mut interpreter = wasm_interpreter();
	test_finalize(interpreter.exec(params, &mut ext)).unwrap();

	assert_eq!(
		ext.store.get(b"address".as_ref()).unwrap(),
		&address_str.as_bytes(),
		"{}",
		std::str::from_utf8(ext.store.get(b"address".as_ref()).unwrap()).unwrap(),
	);
	assert_eq!(
		ext.store.get(b"sender".as_ref()).unwrap(),
		&sender_str.as_bytes()
	);
	assert_eq!(
		ext.store.get(b"value".as_ref()).unwrap(),
		&value.to_string().as_bytes()
	);
}

#[test]
fn io() {
	let code = load_sample!("io");
	let mut params = ActionParams::default();
	params.data = Some(b"hello, world!".to_vec());
	params.gas = U256::from(1_000_000);
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();
	let mut interpreter = wasm_interpreter();
	let (_, return_data, _) = test_finalize(interpreter.exec(params, &mut ext)).unwrap();

	let output = std::str::from_utf8(&*return_data).unwrap();
	assert_eq!(output, "the input was: hello, world!\n");
}

#[test]
fn event() {
	let code = load_sample!("event");
	let mut params = ActionParams::default();
	params.gas = U256::from(1_000_000);
	params.value = ActionValue::Transfer(0.into());
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();

	let mut interpreter = wasm_interpreter();
	test_finalize(interpreter.exec(params, &mut ext)).unwrap();

	assert_eq!(ext.logs.len(), 1);
	let log_entry = &ext.logs[0];
	assert_eq!(log_entry.topics.len(), 3);
	assert_eq!(
		&log_entry.topics[0],
		&ethereum_types::H256::from(
			"0404040400000000000000000000000000000000000000000000000000000000"
		)
	);
	assert_eq!(
		&log_entry.topics[1],
		&ethereum_types::H256::from(
			"0505050505000000000000000000000000000000000000000000000000000000"
		)
	);
	assert_eq!(
		&log_entry.topics[2],
		&ethereum_types::H256::from(
			"0606060606060000000000000000000000000000000000000000000000000000"
		)
	);
	assert_eq!(&log_entry.data, b"hello, world!");
}

#[test]
fn revert_panic() {
	let code = load_sample!("revert_panic");
	let mut params = ActionParams::default();
	params.gas = U256::from(1_000_000);
	params.value = ActionValue::Transfer(0.into());
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();

	let mut interpreter = wasm_interpreter();
	let (gas_left, return_data, apply_state) =
		test_finalize(interpreter.exec(params, &mut ext)).unwrap();
	assert_eq!(apply_state, false);
	assert!(gas_left > 0);
	let output = std::str::from_utf8(&*return_data).unwrap();
	assert!(output.contains("eek!"));
}

#[test]
fn revert_exit() {
	let code = load_sample!("revert_exit");
	let mut params = ActionParams::default();
	params.gas = U256::from(1_000_000);
	params.value = ActionValue::Transfer(0.into());
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();

	let mut interpreter = wasm_interpreter();
	let (gas_left, return_data, apply_state) =
		test_finalize(interpreter.exec(params, &mut ext)).unwrap();
	assert_eq!(apply_state, false);
	assert!(gas_left > 0);
	assert_eq!(std::str::from_utf8(&*return_data).unwrap(), "");
}

#[test]
fn revert_enoent() {
	let code = load_sample!("revert_enoent");
	let mut params = ActionParams::default();
	params.gas = U256::from(1_000_000);
	params.value = ActionValue::Transfer(0.into());
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();

	let mut interpreter = wasm_interpreter();
	let (gas_left, _return_data, apply_state) =
		test_finalize(interpreter.exec(params, &mut ext)).unwrap();
	assert_eq!(apply_state, false);
	assert!(gas_left > 0);
}

#[test]
fn read_delete() {
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
	let (_, return_data, _) = test_finalize(interpreter.exec(params, &mut ext)).unwrap();

	let output = std::str::from_utf8(&*return_data).unwrap();
	assert_eq!(output, val_str);

	assert!(!ext.store.contains_key(&key));
	assert_eq!(ext.sstore_clears, 1);
}

#[test]
fn code_balance() {
	let address: Address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6".parse().unwrap();
	let code = Arc::new(load_sample!("self_code_balance"));
	let balance = 99991u128;
	let mut params = ActionParams::default();
	params.gas = U256::from(1_000_000);
	params.value = ActionValue::Transfer(0.into());
	params.code = Some(Arc::clone(&code));
	params.address = address.clone();

	let mut ext = FakeExt::new().with_wasm();
	ext.codes.insert(address.clone(), Arc::clone(&code));
	ext.balances
		.insert(address.clone(), common_types::u256_from_u128(balance));

	let mut interpreter = wasm_interpreter();
	test_finalize(interpreter.exec(params, &mut ext)).unwrap();

	assert_eq!(ext.store.get(b"the_code".as_ref()), Some(&*code));
	assert_eq!(
		ext.store
			.get(b"the_balance".as_ref())
			.map(|bal| bal.as_slice()),
		Some(balance.to_le_bytes().as_ref())
	);
}

#[test]
fn xcc() {
	let code = load_sample!("xcc_a");
	let caller_address: Address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6".parse().unwrap();
	let callee_address: Address = Address::from([1u8; std::mem::size_of::<Address>()]);
	let value = 42u64;

	let mut params = ActionParams::default();
	params.data = Some(callee_address.to_vec());
	params.address = caller_address.clone();
	params.gas = U256::from(1_000_000);
	params.code = Some(Arc::new(code));
	params.value = ActionValue::transfer(value);
	let mut ext = FakeExt::new().with_wasm();

	let mut interpreter = wasm_interpreter();
	test_finalize(interpreter.exec(params, &mut ext)).unwrap();

	let mut calls_iter = ext.calls.iter();
	let call = calls_iter.next().unwrap();
	assert!(calls_iter.next().is_none());

	assert_eq!(
		*call,
		vm::tests::FakeCall {
			call_type: vm::tests::FakeCallType::Call,
			gas: call.gas.clone(), // this is flaky and will change if gas accounting changes
			sender_address: Some(caller_address),
			receive_address: Some(callee_address),
			value: Some(value.into()),
			data: b"hello, other service!".to_vec(),
			code_address: Some(callee_address)
		}
	);
}

#[test]
fn math_factorial() {
	let code = load_sample!("factorial");
	let mut params = ActionParams::default();
	params.data = Some(b"5".to_vec());
	params.gas = U256::from(1_000_000);
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();

	let mut interpreter = wasm_interpreter();
	let (_, return_data, _) = test_finalize(interpreter.exec(params, &mut ext)).unwrap();

	let output = std::str::from_utf8(&*return_data).unwrap();
	assert_eq!(output, "the output is: 120\n");
}

#[test]
fn math_fib() {
	let code = load_sample!("fibonacci");
	let mut params = ActionParams::default();
	params.data = Some(b"10".to_vec());
	params.gas = U256::from(1_000_000);
	params.code = Some(Arc::new(code));
	let mut ext = FakeExt::new().with_wasm();

	let mut interpreter = wasm_interpreter();
	let (_, return_data, _) = test_finalize(interpreter.exec(params, &mut ext)).unwrap();

	let output = std::str::from_utf8(&*return_data).unwrap();
	assert_eq!(output, "the output is: 89\n");
}
