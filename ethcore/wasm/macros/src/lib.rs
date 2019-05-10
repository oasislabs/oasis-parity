extern crate proc_macro;

#[macro_use]
extern crate syn;
#[macro_use]
extern crate proc_quote;

macro_rules! format_ident {
    ($fmt_str:literal, $($fmt_arg:expr),+) => {
        syn::Ident::new(&format!($fmt_str, $($fmt_arg),+), proc_macro2::Span::call_site())
    }
}

fn export_fn_args(args: &syn::FnDecl) -> impl Iterator<Item = &syn::Type> {
	args.inputs
		.iter()
		.skip(1 /* &self */)
		.filter_map(|inp| match inp {
			syn::FnArg::Captured(syn::ArgCaptured { ty, .. }) => Some(ty),
			_ => None,
		})
}

#[proc_macro_attribute]
pub fn wasm_exports(
	_args: proc_macro::TokenStream,
	input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
	let exports = parse_macro_input!(input as syn::ItemImpl);

	let export_fn_sigs = exports
		.items
		.iter()
		.filter_map(|itm| match itm {
			syn::ImplItem::Method(syn::ImplItemMethod { sig, .. }) => Some(sig),
			_ => None,
		})
		.collect::<Vec<_>>();

	let (id_idents, wsig_idents): (Vec<syn::Ident>, Vec<syn::Ident>) = export_fn_sigs
		.iter()
		.map(|sig| {
			let wasmi_sig_ident = syn::Ident::new(
				&sig.ident.to_string().to_uppercase(),
				proc_macro2::Span::call_site(),
			);
			let id_ident = format_ident!("{}_FUNC", wasmi_sig_ident);
			(wasmi_sig_ident, id_ident)
		})
		.unzip();

	let ids = id_idents.iter().enumerate().map(|(i, id_ident)| {
		quote! { pub const #id_ident: usize = #i; }
	});

	let signatures = export_fn_sigs
		.iter()
		.zip(wsig_idents.iter())
		.map(|(sig, wsig_ident)| {
			let wasm_args =
				export_fn_args(&sig.decl).map(|arg_ty| match wasm_type_for_type(arg_ty) {
					WasmType::I32 => quote!(I32),
					WasmType::I64 => quote!(I64),
				});
			let ret_ty = if sig.ident == "gas" || sig.ident == "proc_exit" {
				quote! { None }
			} else {
				quote! { Some(I32) }
			};
			quote! {
				pub const #wsig_ident: crate::env::StaticSignature =
					crate::env::StaticSignature(&[#(#wasm_args),*], #ret_ty);
			}
		});

	let invokes = export_fn_sigs
		.iter()
		.zip(id_idents.iter())
		.map(|(f, id_ident)| {
			let f_ident = &f.ident;
			let args = (0..(f.decl.inputs.len() - 1/* &self */)).map(|i| {
				quote! { args.nth_checked(#i)? }
			});
			if f_ident == "gas" || f_ident == "proc_exit" {
				quote! {
					ids::#id_ident => {
						self.#f_ident(#(#args),*)?;
						Ok(None)
					}
				}
			} else {
				quote! {
				ids::#id_ident => {
					debug!(target: "wasm",
						   "runtime: call {}", stringify!(#f_ident));
					Ok(Some((self.#f_ident(#(#args),*)? as u16).into()))
				}
				}
			}
		});

	let resolver_arms = export_fn_sigs
		.iter()
		.zip(id_idents.iter().zip(wsig_idents.iter()))
		.map(|(f, (id_ident, sig_ident))| {
			let f_ident = &f.ident;
			quote! {
				stringify!(#f_ident) => {
					crate::env::host(signatures::#sig_ident, ids::#id_ident)
				}
			}
		});

	proc_macro::TokenStream::from(quote! {
		const _impl_wasi_runtime: () = {
			#exports

			mod ids {
				#(#ids)*
			}

			mod signatures {
				use wasmi::ValueType::*;
				use wasmi::{self, ValueType};

				#(#signatures)*
			}

			const _impl_ModuleImportResolver_for_ImportResolver: () = {
				impl wasmi::ModuleImportResolver for crate::env::ImportResolver {
					fn resolve_func(
						&self,
						field_name: &str,
						_signature: &wasmi::Signature
					) -> std::result::Result<wasmi::FuncRef, wasmi::Error> {
						Ok(match field_name {
							#(#resolver_arms)*
							_ => {
								return Err(wasmi::Error::Instantiation(format!(
									"Export {} not found ({:?})",
									field_name,
									_signature,
								)))
							}
						})
					}

					fn resolve_memory(
						&self,
						field_name: &str,
						descriptor: &wasmi::MemoryDescriptor,
					) -> Result<wasmi::MemoryRef, wasmi::Error> {
						if field_name == "memory" {
							let effective_max = descriptor
								.maximum()
								.unwrap_or(self.max_memory);
							if descriptor.initial() > self.max_memory ||
								effective_max > self.max_memory {
								Err(wasmi::Error::Instantiation(format!(
									"Module requested too much memory: initial={}, effective={}, max={}",
									descriptor.initial(),
									effective_max,
									self.max_memory
								)))
							} else {
								let mem = wasmi::MemoryInstance::alloc(
									wasmi::memory_units::Pages(descriptor.initial() as usize),
									descriptor
										.maximum()
										.map(|x| wasmi::memory_units::Pages(x as usize)),
								)?;
								*self.memory.borrow_mut() = Some(mem.clone());
								Ok(mem)
							}
						} else {
							Err(wasmi::Error::Instantiation(
								"Memory imported under unknown name".to_owned(),
							))
						}
					}
				}
			};

			const _impl_Externals_for_Runtime: () = {
				impl<'a> wasmi::Externals for crate::runtime::Runtime<'a> {
					fn invoke_index(
						&mut self,
						index: usize,
						args: wasmi::RuntimeArgs,
					) -> std::result::Result<Option<wasmi::RuntimeValue>, wasmi::Trap> {
						match index {
							#(#invokes)*
							_ => panic!("env module doesn't provide function at index {}", index),
						}
					}
				}
			};
		};
	})
}

enum WasmType {
	I32,
	I64,
}

fn wasm_type_for_type(ty: &syn::Type) -> WasmType {
	match ty {
		syn::Type::Path(syn::TypePath { path, .. }) => {
			if path.is_ident("Timestamp")
				|| path.is_ident("UserData")
				|| path.is_ident("Device")
				|| path.is_ident("DirCookie")
				|| path.is_ident("FileDelta")
				|| path.is_ident("FileSize")
				|| path.is_ident("Inode")
				|| path.is_ident("Rights")
			{
				WasmType::I64
			} else {
				WasmType::I32
			}
		}
		_ => panic!("Bad type {:?}", ty),
	}
}
