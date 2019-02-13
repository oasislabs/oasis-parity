use ethereum_types::H256;
use evm::CallType;
use std::sync::Arc;
use vm::{self, ActionParams, Vm, Ext, GasLeft, Result, ReturnData};

/// The H256 topic that the long term public key is logged under for a confidential deploy.
const CONFIDENTIAL_LOG_TOPIC: &'static str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// ConfidentialVm is a wrapper around a WASM or EVM vm for executing confidential contracts.
pub struct ConfidentialVm {
	/// Underlying EVM or WASM vm to execute decrypted transactions.
	vm: Box<vm::Vm>
}

impl Vm for ConfidentialVm {
	fn exec(&mut self, params: ActionParams, ext: &mut Ext) -> Result<GasLeft> {
		match params.call_type {
			CallType::None => self.exec_create(params, ext),
			_ => self.exec_call(params, ext)
		}
	}
}

impl ConfidentialVm {
	pub fn new(vm: Box<vm::Vm>) -> Self {
		ConfidentialVm { vm }
	}

	/// Deploys a confidential contract, executing the init code and ensuring the
	/// CONFIDENTIAL_PREFIX is prepended to the stored account bytecode.
	///
	/// Assumes the prefix has been removed from the initcode in `no_prefix_params`.
	fn exec_create(&mut self, no_prefix_params: ActionParams, ext: &mut Ext) -> Result<GasLeft> {
		let (public_key, mut signature) = ext.create_long_term_public_key(no_prefix_params.code_address.clone())?;

        let mut log_data = public_key;
        log_data.append(&mut signature);
		// store public key in log for retrieval
		ext.log(
			vec![H256::from(CONFIDENTIAL_LOG_TOPIC)],
			&log_data
		)?;

        // open the confidential context so that we can transparently encrypt/decrypt
		let _ = ext.open_confidential_ctx(
			no_prefix_params.address,
            None
		)?;

		// execute the init code with the underlying vm
		let result = self.vm.exec(no_prefix_params, ext)?;

        // shut down the confidential ctx so we stop encrypting
		ext.close_confidential_ctx();

		Ok(result)
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

		// open the confidential context so that we can transparently encrypt/decrypt
		let unencrypted_tx_data = ext.open_confidential_ctx(
			no_prefix_params.address,
			Some(no_prefix_params.data.as_ref().unwrap().to_vec())
		)?;

		// execute the transaction on the underlying EVM/WASM vm
		no_prefix_params.data = Some(unencrypted_tx_data);
		let result = Self::encrypt_vm_result(
			self.vm.exec(no_prefix_params, ext)?,
			ext
		);

		// shut down the confidential ctx so we stop encrypting
		ext.close_confidential_ctx();

		result
	}

	/// Encrypts the execution result of a confidential call.
	/// Assumes the encryption context of ext has already been set.
	fn encrypt_vm_result(result: GasLeft, ext: &mut Ext) -> vm::Result<GasLeft> {
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
