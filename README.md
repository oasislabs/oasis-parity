# Parity

Forked from https://github.com/paritytech/parity/.

Major changes made by Oasis Labs:
* Parity runtime modified to run in Intel SGX, using [Fortanix Rust Enclave Development Platform] (https://github.com/fortanix/rust-sgx).
* Support for confidential smart contracts: transactions encrypted end-to-end and contract state encrypted in storage.
* [Blockchain WASI](https://github.com/oasislabs/rfcs/pull/1)-based runtime for WebAssembly contracts.
* Option to use [Wasmer](https://github.com/wasmerio/wasmer) WebAssembly runtime rather than the standard [wasmi interpreter](https://github.com/oasislabs/wasmi).
