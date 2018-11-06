use ethereum_types::H256;
use evm::CallType;
use std::sync::Arc;
use vm::{self, ActionParams, Vm, Ext, GasLeft, Result, ReturnData};

/// 4 byte prefix prepended to all confidential contract bytecode.
const CONFIDENTIAL_PREFIX: &'static [u8; 4] = b"\0enc";
/// The H256 topic that the long term public key is logged under for a confidential deploy.
const CONFIDENTIAL_LOG_TOPIC: &'static str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// ConfidentialVm is a wrapper around a WASM or EVM vm for executing confidential contracts.
pub struct ConfidentialVm {
	/// Underlying EVM or WASM vm to execute decrypted transactions.
	vm: Box<vm::Vm>
}

impl Vm for ConfidentialVm {
	fn exec(&mut self, params: ActionParams, ext: &mut Ext) -> Result<GasLeft> {
		let mut no_prefix_params = params.clone();
		no_prefix_params.code = params.code.map(|code| Arc::new(Self::remove_prefix(code.to_vec())));
		match params.call_type {
			CallType::None => self.exec_create(no_prefix_params, ext),
			_ => self.exec_call(no_prefix_params, ext)
		}
	}
}

impl ConfidentialVm {
	pub fn new(vm: Box<vm::Vm>) -> Self {
		ConfidentialVm { vm }
	}

	/// Returns true if the given bytecode represents a confidential contract.
	/// Errors if the bytecode is not confidential, but we've compiled with both
	/// the enable-confidential and disable-non-confidential features.
	pub fn is_confidential(bytecode: Option<&[u8]>) -> Result<bool> {
		if cfg!(feature = "enable-confidential") {
			match bytecode {
				None => {
					if cfg!(feature = "disable-non-confidential") {
						Err(vm::Error::Internal("Bytecode can't be None in exclusively confidential mode".to_string()))
					} else {
						Ok(false)
					}
				},
				Some(code) => {
					if !Self::has_confidential_prefix(code) {
						if cfg!(feature = "disable-non-confidential") {
							Err(vm::Error::Internal("Bytecode must always have confidential prefix".to_string()))
						} else {
							Ok(false)
						}
					} else {
						Ok(true)
					}
				}
			}
		} else {
			Ok(false)
		}
	}

	fn has_confidential_prefix(bytecode: &[u8]) -> bool {
		if bytecode.len() < CONFIDENTIAL_PREFIX.len() {
			return false;
		}
		let prefix = &bytecode[..CONFIDENTIAL_PREFIX.len()];
		return prefix == CONFIDENTIAL_PREFIX;
	}

	/// Strips the prefix off the given bytecode, so that it can be executed normally.
	/// Assumes is_confidential is true.
	pub fn remove_prefix(bytecode: Vec<u8>) -> Vec<u8> {
		bytecode[CONFIDENTIAL_PREFIX.len()..].to_vec()
	}

	/// Prepends the CONFIDENTIAL_PREFIX to the given bytecode, marking it as a
	/// confidential contract. Assumes is_confidential is false.
	fn add_prefix(mut bytecode: Vec<u8>) -> Vec<u8> {
		let mut prefix = CONFIDENTIAL_PREFIX.to_vec();
		prefix.append(&mut bytecode);
		prefix
	}

	/// Deploys a confidential contract, executing the init code and ensuring the
	/// CONFIDENTIAL_PREFIX is prepended to the stored account bytecode.
	///
	/// Assumes the prefix has been removed from the initcode in `no_prefix_params`.
	fn exec_create(&mut self, no_prefix_params: ActionParams, ext: &mut Ext) -> Result<GasLeft> {
		let pk = ext.long_term_public_key(no_prefix_params.code_address.clone())?;
		// store public key in log for retrieval
		ext.log(
			vec![H256::from(CONFIDENTIAL_LOG_TOPIC)],
			&pk
		);
		// execute the init code with the underlying vm
		let result = self.vm.exec(no_prefix_params, ext)?;
		// prepend CONFIDENTIAL_PREFIX to the bytecode that is eventually stored in the account
		if let GasLeft::NeedsReturn { gas_left, data, apply_state } = result {
			let confidential_bytecode = Self::add_prefix(data.to_vec());
			let size = confidential_bytecode.len();
			return Ok(GasLeft::NeedsReturn {
				gas_left,
				data: ReturnData::new(confidential_bytecode, 0, size),
				apply_state
			});
		}
		Err(vm::Error::Internal("Expected to receive returned bytecode".to_string()))
	}

	/// Makes a confidential contract call, decrypting the transaction's calldata if needed.
	/// Assumes the CONFIDENTIAL_PREFIX has been removed from contract bytecode in `no_prefix_params`.
	/// Returns the result of executing the contract call, encrypted with key given in the
	/// encrypted calldata.
	fn exec_call(&mut self, mut no_prefix_params: ActionParams, ext: &mut Ext) -> Result<GasLeft> {
		if no_prefix_params.data.is_none() {
			return Err(vm::Error::Internal(
				"Cannot execute a confidential call without a data field".to_string()
			));
		}
		let (_nonce, key, data) = {
			let encrypted_data = no_prefix_params.data.as_ref().unwrap();
			ext.decrypt(encrypted_data.to_vec())?
		};
		no_prefix_params.data = Some(data);
		// open the externalities' encryption context so that logs are encrypted
		ext.set_encryption_key(Some(key));
		let result = Self::encrypt_vm_result(
			self.vm.exec(no_prefix_params, ext)?,
			ext
		);
		// close the encryption context
		ext.set_encryption_key(None);
		result
	}

	/// Encrypts the execution result of a confidential call.
	/// Assumes the encryption context of ext has already been set.
	fn encrypt_vm_result(result: GasLeft, ext: &Ext) -> vm::Result<GasLeft> {
		if let GasLeft::NeedsReturn { gas_left, data, apply_state} = result {
			let enc_data = ext.encrypt(data.to_vec())?;
			let enc_data_len = enc_data.len();
			let result = GasLeft::NeedsReturn {
				gas_left, data: ReturnData::new(enc_data, 0, enc_data_len), apply_state
			};
			return Ok(result);
		}
		Ok(result)
	}
}
