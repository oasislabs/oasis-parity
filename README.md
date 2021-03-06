# Parity

[![CircleCI](https://circleci.com/gh/oasislabs/oasis-parity.svg?style=svg)](https://circleci.com/gh/oasislabs/oasis-parity)
[![Coverage Status](https://coveralls.io/repos/github/oasislabs/oasis-parity/badge.svg)](https://coveralls.io/github/oasislabs/oasis-parity)

Forked from https://github.com/paritytech/parity-ethereum/.

Major changes made by Oasis Labs:
* Parity runtime modified to run in Intel SGX, using the [Fortanix Rust Enclave Development Platform](https://github.com/fortanix/rust-sgx).
* Support for *confidential smart contracts*: transactions encrypted end-to-end and contract state encrypted in storage.
* [Blockchain WASI](https://github.com/oasislabs/rfcs/pull/1)-based runtime for WebAssembly contracts.

For an example of how to use, see https://github.com/oasislabs/oasis-chain.
