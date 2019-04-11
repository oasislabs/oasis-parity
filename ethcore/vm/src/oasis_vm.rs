use ethereum_types::{Address, H256};
use std::{cell::RefCell, rc::Rc};
use crate::{ActionParams, OasisContract, Vm, Ext, GasLeft, Result, Error, ReturnData, CallType};

/// The H256 topic that the long term public key is logged under for a confidential deploy.
const CONFIDENTIAL_LOG_TOPIC: &'static str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// OasisVm is a wrapper for a WASM or EVM vm for executing all contracts on Oasis.
pub struct OasisVm {
	// Internal VM performing the actual execution.
	vm: Box<Vm>
}

impl Vm for OasisVm {
	fn exec(&mut self, params: ActionParams, ext: &mut Ext) -> Result<GasLeft> {
		// If this is a create with a header, copy the raw header bytes to prepend to the bytecode.
		let header = {
			if params.call_type == CallType::None {
				params.oasis_contract.as_ref().map(|c| c.header.clone())
			} else {
				None
			}
		};

		let result = self.vm.exec(params, ext);

		// Prepend the header to the bytecode that is stored in the account.
		if let Some(bytes) = header {
			if let Ok(GasLeft::NeedsReturn { gas_left, data, apply_state }) = result {
				let mut bytecode = bytes;
				bytecode.append(&mut data.to_vec());
				let size = bytecode.len();
				return Ok(GasLeft::NeedsReturn {
					gas_left,
					data: ReturnData::new(bytecode, 0, size),
					apply_state
				})
			}
		}

		result
	}
}

impl OasisVm {
	pub fn new(ctx: Option<Rc<RefCell<Box<ConfidentialCtx>>>>, vm: Box<Vm>) -> Self {
		let vm = match ctx {
			None => vm,
			Some(ctx) => Box::new(ConfidentialVm { ctx, vm })
		};
		OasisVm { vm }
	}
}

/// Vm execution of confidential transactions.
struct ConfidentialVm {
	/// The confidential context attached to the state.
	ctx: Rc<RefCell<Box<ConfidentialCtx>>>,
	/// Underlying EVM or WASM vm to execute raw (decrypted) transactions.
	vm: Box<Vm>,
}

impl Vm for ConfidentialVm {
	fn exec(&mut self, params: ActionParams, ext: &mut Ext) -> Result<GasLeft> {
		// Executes confidentially.
		if self.is_confidential(&params, ext)? {
			self.exec_confidential(params, ext)
		}
		// Excutes non-confidentially.
		else {
			self.vm.exec(params, ext)
		}
	}
}

impl ConfidentialVm {

	/// Returns true if the given `params` and `ext` should be executed confidentially.
	fn is_confidential(&self, params: &ActionParams, ext: &mut Ext) -> Result<bool> {
		// If we've ever executed a confidential contract at any point in the transaction
		// then keep treating as confidential, so that we can switch into and out of
		// confidentiality.
		if self.ctx.borrow().activated() {
			Ok(true)
		}
		// If we're creating a confidential contract, then check the params' code, since
		// it's not yet part of the state.
		else if ext.depth() == 0 && params.call_type == CallType::None {
			Ok(params.oasis_contract.as_ref().map_or(false, |c| c.confidential))
		}
		// If we haven't executed a confidential contract in this transaction yet, check
		// if the target contract is confidential. Don't check the given oasis_contract
		// since that is the contract of the code *being executed*. For cross contract
		// calls, we need to check the code of the storage context with which we are in,
		// E.g., in a delgatecall, this is *not* the same as the code being executed.
		else {
			ext.is_confidential_contract(&params.address)
		}
	}

	fn exec_confidential(&mut self, params: ActionParams, ext: &mut Ext) -> Result<GasLeft> {
		let result = {
			if ext.depth() == 0 {
				self.tx(params, ext)
			} else {
				self.cross_contract_call(params, ext)
			}
		};

		if result.is_err() {
			self.ctx.borrow_mut().deactivate();
		}

		result
	}

	/// Executes a top level transaction, i.e., params are given from the client.
	fn tx(&mut self, params: ActionParams, ext: &mut Ext) -> Result<GasLeft> {
		assert!(!self.ctx.borrow().activated() && ext.depth() == 0);

		match params.call_type {
			CallType::None => self.tx_create(params, ext),
			_ => self.tx_call(params, ext)
		}
	}

	/// Deploys a confidential contract.
	fn tx_create(&mut self, params: ActionParams, ext: &mut Ext) -> Result<GasLeft> {
		let (public_key, mut signature)
			= self.ctx.borrow_mut().create_long_term_public_key(params.code_address.clone())?;

		let mut log_data = public_key;
		log_data.append(&mut signature);
		// Store public key in log for retrieval.
		ext.log(
			vec![H256::from(CONFIDENTIAL_LOG_TOPIC)],
			&log_data
		)?;

		// Activate the confidential context so that we can transparently encrypt/decrypt.
		self.ctx.borrow_mut().activate(Some(params.address))?;

		// Execute the init code with the underlying vm.
		let result = self.vm.exec(params, ext);

		// Shut down the confidential ctx so we stop encrypting.
		self.ctx.borrow_mut().deactivate();

		result
	}

	/// Makes a top level confidential contract call, decrypting the transaction's data field.
	/// *Not* a cross-contract call.
	///
	/// Returns the result of executing the contract call, encrypted with key given in the
	/// encrypted calldata.
	fn tx_call(&mut self, mut params: ActionParams, ext: &mut Ext) -> Result<GasLeft> {
		if params.data.is_none() {
			return Err(Error::Confidential(
				"Cannot execute a confidential call without a data field".to_string()
			));
		}

		// Activate the confidential context so that we can transparently encrypt/decrypt.
		let _ = self.ctx.borrow_mut().activate(Some(params.address));

		// Replace the Action's data payload with the unencrypted version.
		let unencrypted_tx_data = self.ctx.borrow_mut().decrypt_session(
			params.data.as_ref().unwrap().to_vec()
		)?;
		params.data = Some(unencrypted_tx_data);

		// Execute the code and encrypt the result.
		let encrypted_result = {
			let result = self.vm.exec(params, ext)?;
			self.encrypt_vm_result(result, ext)
		};

		// Shut down the confidential ctx to stop encrypting.
		self.ctx.borrow_mut().deactivate();

		encrypted_result
	}

	/// Encrypts the execution result of a confidential call.
	fn encrypt_vm_result(&self, result: GasLeft, ext: &mut Ext) -> Result<GasLeft> {
		if let GasLeft::NeedsReturn { gas_left, data, apply_state} = result {
			let enc_data = self.ctx.borrow_mut().encrypt_session(data.to_vec())?;
			let enc_data_len = enc_data.len();
			let result = GasLeft::NeedsReturn {
				gas_left, data: ReturnData::new(enc_data, 0, enc_data_len), apply_state
			};
			return Ok(result);
		}
		Ok(result)
	}

	/// Executes a confidential cross contract call. Here, a confidential context is already active,
	/// so just perform a context switch by swapping the underlying contract encryption keys.
	///
	/// Note that, in this case, the input payload is not encrypted. I.e.,
	/// if we have a transaction execution of the form
	///
	/// client -> conf_contract_A -> conf_contract_B,
	///
	/// then the transaction from client -> conf_contract_A *is* encrypted, but
	/// since we're already in the enclave, theres no need to encrypt the call from
	/// conf_contract_A -> conf_contract_B.
	///
	/// However, we could do such additional encryption/decryption *here*. This would be
	/// useful if we wanted to exit out of the enclave with encrypted data and enter into
	/// a new enclave in the future.
	fn cross_contract_call(&mut self, mut params: ActionParams, ext: &mut Ext) -> Result<GasLeft> {
		self.check_cross_contract_call(&params, ext)?;

		let address = {
			if ext.is_confidential_contract(&params.address)? {
				Some(params.address)
			} else {
				None
			}
		};

		// Swap the confidential context to the new contract we're calling. If it's a
		// delegatecall/callcode, then this switch is a no-op.
		//
		// Note: params.address is *not* necessarily the address of the target
		// contract we're executing. If executing a delegatecall or callcode, then it is
		// the address whose storage context we're executing in.
		let old_contract = self.ctx.borrow_mut().activate(address)?;

		// Run the contract execution.
		let result = self.vm.exec(params, ext);

		// Swap back the confidential ctx to use the keys prior to the cross contract call.
		let _ = self.ctx.borrow_mut().activate(old_contract)?;

		result
	}

	fn check_cross_contract_call(&self, params: &ActionParams, ext: &mut Ext) -> Result<()> {
		if params.call_type == CallType::None {
			return Err(Error::Confidential(
				"Cannot create a contract after executing a confidential contract".to_string()
			));
		}
		if params.data.is_none() {
			return Err(Error::Confidential(
				"Cannot execute a confidential call without a data field".to_string()
			));
		}

		// To enable cross contract calls across confidential domains, remove the following checks.

		// Assert confidential contracts can only call confidential contracts.
		if self.ctx.borrow().activated() && !ext.is_confidential_contract(&params.address)? {
			return Err(Error::Confidential("cannot call a non-confidential contract from confidential".to_string()));
		}
		// Assert non-confidnetial contracts can only call non-confidential contracts.
		if !self.ctx.borrow().activated() && ext.is_confidential_contract(&params.address)? {
			return Err(Error::Confidential("cannot call a confidential contract from non-confidential".to_string()));
		}
		Ok(())
	}
}

/// ConfidentialCtx provides a collection of services to be *controlled* by the OasisVm
/// and *observed* by the ethcore State to enable confidential contracts.
///
/// The expected usage is to use `activate` to enable the confidential context for a given
/// contract, at which point any of the other methods can be called, e.g.,
/// to encrypt/decrypt storage or logs.
///
/// When encrypting to a `peer()` with `encrypt_session`, `decrypt_session`  must first be
/// called to set the peer receiving such encrypted payloads.
///
/// When accessing storage or logs, the ethcore State observes the shared OasisVm confidential ctx,
/// and uses encryption if necessary.
///
/// Upon completion,  one should call `deactivate` to clear the confidential context.
pub trait ConfidentialCtx {
	/// Activates the ConfidentialCtx to encrypt and decrypt all state for the given `contract`.
	///
	/// If already activated performs a confidential context switch, swapping the keys for the
	/// currently activated contract for the given one.
	///
	/// If `contract` is None, then the ConfidentialCtx will stop encrypting.
	///
	/// Returns the address of the contract for the old encryption context.
	fn activate(&mut self, contract: Option<Address>) -> Result<Option<Address>>;
	/// Deactivates the context. If called, subsequent calls to `encrypt_*` should fail.
	fn deactivate(&mut self);
	/// Returns true if a confidential contract has previously been called.
	fn activated(&self) -> bool;
	/// Returns true if the confidential context is encrypting the state's storage.
	fn is_encrypting(&self) -> bool;
	/// Encrypts the given data under the given context, i.e., using the active session
	/// and contract keys so that the *client* which initiated the transaction to open the
	/// context can decrypt the data. Returns an error if the confidential context is
	/// not open.
	fn encrypt_session(&mut self, data: Vec<u8>) -> Result<Vec<u8>>;
	/// Decrypting a session sets the context such that subsequent calls to `encrypt_sesion`
	/// are targeted at the session `peer()`.
	///
	/// Assumes `encrypted_payload` is of the form	NONCE || PEER_PUBLIC_SESSION_KEY || CIPHER.
	fn decrypt_session(&mut self, encrypted_payload: Vec<u8>) -> Result<Vec<u8>>;
	/// Returns the public key of the peer connecting through an encrypted session to the runtime.
	/// Returns None if no such key exists, e.g., if a confidential contract is being created.
	fn peer(&self) -> Option<Vec<u8>>;
	/// Encrypts the given data to be placed into contract storage	under the context.
	/// The runtime allows *only a given contract* to encrypt/decrypt this data, as
	/// opposed to the `encrypt` method, which allows a user's client to decrypt.
	fn encrypt_storage(&self, data: Vec<u8>) -> Result<Vec<u8>>;
	/// Analog to `encrypt_storage` for decyrpting data.
	fn decrypt_storage(&self, data: Vec<u8>) -> Result<Vec<u8>>;
	/// Creates the long term public key for the given contract. If it already
	/// exists, returns the existing key. The first item is the key, the second
	/// is a signature over the key by the KeyManager.
	fn create_long_term_public_key(&mut self, contract: Address) -> Result<(Vec<u8>, Vec<u8>)>;
}
