use std::convert::{TryFrom, TryInto};

use crate::U256;
use wasi_types::*;

use wasmer_runtime_core::memory::ptr::{Array, Item, WasmPtr};
use wasmer_runtime_core::vm::Ctx;

const ADDR_LEN_BYTES: usize = std::mem::size_of::<mantle_types::Address>();
const ADDR_CHARS: usize = ADDR_LEN_BYTES * 2; // two hex digits per byte

macro_rules! bcfs {
	( $self:ident . bcfs . $fn:ident ( $($args:expr),+ )  ) => {
		// Unsafety is required because BCFS is mutably borrowed with `self`
		// but also takes a `PendingTransaction` which also happens to be `self.
		// This is okay because BCFS doesn't modify itself through `PendingTransaction`.
		match unsafe { &mut *$self.bcfs.get() }.$fn($self, $( $args ),+ ) {
			Ok(result) => result,
			Err(errno) => return Ok(errno as u16)
		}
	}
}

impl<'a> crate::Runtime<'a> {
	// not part of wasi, but required by parity
	pub fn gas(&mut self, amount: u32) -> crate::Result<()> {
		if self.charge_gas(amount as u64) {
			Ok(())
		} else {
			Err(crate::runtime::Error::GasLimit.into())
		}
	}

	pub fn args_get(
		&mut self,
		ctx: &mut Ctx,
		argv: WasmPtr<WasmPtr<u8, Array>, Array>,
		argv_buf: WasmPtr<u8, Array>,
	) -> crate::Result<u16> {
		Ok(ErrNo::Success as u16)
	}

	pub fn args_sizes_get(
		&mut self,
		ctx: &mut Ctx,
		argc: WasmPtr<u32>,
		_argv_buf_size: WasmPtr<u32>,
	) -> crate::Result<u16> {
		let memory = ctx.memory(0);
		self.memory_set_value(ctx, argc.offset(), 0)?;
		Ok(ErrNo::Success as u16)
	}

	pub fn clock_res_get(
		&mut self,
		ctx: &mut Ctx,
		clock_id: u8,
		resolution: WasmPtr<Timestamp>,
	) -> crate::Result<u16> {
		let clock_id_converted = ClockId::try_from(clock_id).unwrap();
		self.memory_set_value(
			ctx,
			resolution.offset(),
			match clock_id_converted {
				ClockId::RealTime | ClockId::Monotonic => Timestamp::from_nanos(250 * 1_000_000),
				_ => return Ok(ErrNo::Inval as u16),
			},
		)?;
		Ok(ErrNo::Success as u16)
	}

	pub fn clock_time_get(
		&mut self,
		ctx: &mut Ctx,
		clock_id: u8,
		_precision: u64,
		time: WasmPtr<Timestamp>,
	) -> crate::Result<u16> {
		let clock_id_converted = ClockId::try_from(clock_id).unwrap();
		match clock_id_converted {
			ClockId::RealTime | ClockId::Monotonic => self.memory_set_value(
				ctx,
				time.offset(),
				Timestamp::from_sec(self.ext.env_info().timestamp),
			)?,
			_ => return Ok(ErrNo::Inval as u16),
		}
		Ok(ErrNo::Success as u16)
	}

	pub fn environ_get(
		&mut self,
		ctx: &mut Ctx,
		environ: WasmPtr<WasmPtr<u8>>,
		mut environ_buf: WasmPtr<u8>,
	) -> crate::Result<u16> {
		let environs = self
			.memory_get_mut::<WasmPtr<u8>>(ctx, environ.offset(), 3)
			.unwrap();

		environs[0] = environ_buf;
		environ_buf = self
			.memory_set(
				ctx,
				environ_buf.offset(),
				format!("ADDRESS={:x}\0", self.context.address).as_bytes(),
			)
			.unwrap();
		environs[1] = environ_buf;
		environ_buf = self
			.memory_set(
				ctx,
				environ_buf.offset(),
				format!("SENDER={:x}\0", self.context.sender).as_bytes(),
			)
			.unwrap();
		environs[2] = environ_buf;
		self.memory_set(
			ctx,
			environ_buf.offset(),
			format!("VALUE={}", self.context.value_str).as_bytes(),
		)
		.unwrap();
		Ok(ErrNo::Success as u16)
	}

	pub fn environ_sizes_get(
		&mut self,
		ctx: &mut Ctx,
		environ_count: WasmPtr<u32>,
		environ_buf_size: WasmPtr<u32>,
	) -> crate::Result<u16> {
		self.memory_set_value(ctx, environ_count.offset(), 3u32)?; // sender, address, value
		self.memory_set_value(
			ctx,
			environ_buf_size.offset(),
			("SENDER=".len()
				+ ADDR_CHARS + "\0ADDRESS=".len()
				+ ADDR_CHARS + "\0VALUE=".len()
				+ self.context.value_str.len()) as u32,
		)
		.unwrap();
		Ok(ErrNo::Success as u16)
	}

	pub fn fd_advise(
		&mut self,
		_fd: u32,
		_offset: u64,
		_len: u64,
		_advice: u8,
	) -> crate::Result<u16> {
		// unimplemented(todo): advice is an optimization and can be ignored
		Ok(ErrNo::Success as u16)
	}

	pub fn fd_allocate(&mut self, _fd: u32, _offset: u64, _len: u64) -> crate::Result<u16> {
		// unimplemented(dontneed): storage is allocated on demand
		Ok(ErrNo::Success as u16)
	}

	pub fn fd_close(&mut self, ctx: &mut Ctx, fd: u32) -> crate::Result<u16> {
		let fd_converted = Fd::try_from(fd).unwrap();
		bcfs!(self.bcfs.close(fd_converted));
		Ok(ErrNo::Success as u16)
	}

	pub fn fd_datasync(&mut self, fd: u32) -> crate::Result<u16> {
		let fd_converted = Fd::try_from(fd).unwrap();
		bcfs!(self.bcfs.flush(fd_converted));
		Ok(ErrNo::Success as u16)
	}

	pub fn fd_fdstat_get(
		&mut self,
		ctx: &mut Ctx,
		fd: u32,
		buf: WasmPtr<FdStat>,
	) -> crate::Result<u16> {
		let fd_val = Fd::try_from(fd).unwrap();
		let stats = bcfs!(self.bcfs.fdstat(fd_val));
		self.memory_set_value(ctx, buf.offset(), stats).unwrap();
		Ok(ErrNo::Success as u16)
	}

	pub fn fd_fdstat_set_flags(&mut self, _fd: u32, _flags: u16) -> crate::Result<u16> {
		Ok(ErrNo::NotCapable as u16)
	}

	pub fn fd_fdstat_set_rights(
		&mut self,
		_fd: u32,
		_rights_base: u64,
		_rights_inheriting: u64,
	) -> crate::Result<u16> {
		Ok(ErrNo::NotCapable as u16)
	}

	pub fn fd_filestat_get(
		&mut self,
		ctx: &mut Ctx,
		fd: u32,
		buf: WasmPtr<FileStat>,
	) -> crate::Result<u16> {
		let fd_val = Fd::try_from(fd).unwrap();
		self.memory_set_value(ctx, buf.offset(), bcfs!(self.bcfs.filestat(fd_val)))?;
		Ok(ErrNo::Success as u16)
	}

	pub fn fd_filestat_set_size(&mut self, _fd: u32, _size: u64) -> crate::Result<u16> {
		// unimplemented(dontneed): storage is immutable and allocated on demand
		Ok(ErrNo::Success as u16)
	}

	pub fn fd_filestat_set_times(
		&mut self,
		_fd: u32,
		_atime: u64,
		_mtime: u64,
		_flags: u16,
	) -> crate::Result<u16> {
		// unimplemented(todo): vfs doesn't keep track of metadata
		Ok(ErrNo::NoSys as u16)
	}

	pub fn fd_pread(
		&mut self,
		ctx: &mut Ctx,
		fd: u32,
		iovs: WasmPtr<IoVec, Array>,
		iovs_len: u32,
		offset: u64,
		nread: WasmPtr<Size, Array>,
	) -> crate::Result<u16> {
		let fd_converted = Fd::try_from(fd).unwrap();
		self.do_read(ctx, fd_converted, iovs, iovs_len, Some(offset), nread)
	}

	pub fn fd_prestat_dir_name(
		&mut self,
		ctx: &mut Ctx,
		fd: u32,
		path_ptr: WasmPtr<u8>,
		path_len: u32,
	) -> crate::Result<u16> {
		let memory = ctx.memory(0);
		let fd_val = Fd::try_from(fd).unwrap();
		let path_str = bcfs!(self.bcfs.prestat(fd_val)).to_str().unwrap();

		self.memory_set(ctx, path_ptr.offset(), path_str.as_bytes())
			.unwrap();
		self.memory_set_value(ctx, path_len, path_str.len() as u8)
			.unwrap();
		Ok(ErrNo::Success as u16)
	}

	pub fn fd_prestat_get(
		&mut self,
		ctx: &mut Ctx,
		fd: u32,
		buf: WasmPtr<Prestat>,
	) -> crate::Result<u16> {
		let memory = ctx.memory(0);
		let fd_val = Fd::try_from(fd).unwrap();
		let path_str = bcfs!(self.bcfs.prestat(fd_val)).to_str().unwrap();

		self.memory_set_value(
			ctx,
			buf.offset(),
			Prestat {
				resource_type: PreopenType::Dir {
					name_len: match path_str.len().try_into() {
						Ok(name_len) => name_len,
						Err(_) => return Ok(ErrNo::NameTooLong as u16),
					},
				},
			},
		)
		.unwrap();
		Ok(ErrNo::Success as u16)
	}

	pub fn fd_pwrite(
		&mut self,
		ctx: &mut Ctx,
		fd: u32,
		iovs: WasmPtr<IoVec>,
		iovs_len: u32,
		offset: u64,
		nwritten: WasmPtr<Size>,
	) -> crate::Result<u16> {
		let fd_converted = Fd::try_from(fd).unwrap();
		self.do_write(ctx, fd_converted, iovs, iovs_len, Some(offset), nwritten)
	}

	pub fn fd_read(
		&mut self,
		ctx: &mut Ctx,
		fd: u32,
		iovs: WasmPtr<IoVec, Array>,
		iovs_len: u32,
		nread: WasmPtr<Size, Array>,
	) -> crate::Result<u16> {
		let fd_converted = Fd::try_from(fd).unwrap();
		self.do_read(
			ctx,
			fd_converted,
			iovs,
			Size::try_from(iovs_len).unwrap(),
			None,
			nread,
		)
	}

	pub fn fd_readdir(
		&mut self,
		_fd: u32,
		_buf: WasmPtr<u8>,
		_buf_len: u32,
		_dircookie: u64,
		_buf_used: WasmPtr<u32>,
	) -> crate::Result<u16> {
		Ok(ErrNo::NoSys as u16) // unimplemented(todo): vfs doesn't have directories
	}

	pub fn fd_renumber(&mut self, from: u32, to: u32) -> crate::Result<u16> {
		let from_converted = Fd::try_from(from).unwrap();
		let to_converted = Fd::try_from(to).unwrap();
		bcfs!(self.bcfs.renumber(from_converted, to_converted));
		Ok(ErrNo::Success as u16)
	}

	pub fn fd_seek(
		&mut self,
		ctx: &mut Ctx,
		fd: u32,
		offset: i64,
		whence: u8,
		new_offset: WasmPtr<FileSize>,
	) -> crate::Result<u16> {
		let fd_converted = Fd::try_from(fd).unwrap();
		let whence_converted = Whence::try_from(whence).unwrap();
		let new_pos = bcfs!(self.bcfs.seek(fd_converted, offset, whence_converted));
		self.memory_set_value(ctx, new_offset.offset(), new_pos)?;
		Ok(ErrNo::Success as u16)
	}

	pub fn fd_sync(&mut self, fd: u32) -> crate::Result<u16> {
		self.fd_datasync(fd) // there's no metadata
	}

	pub fn fd_tell(
		&mut self,
		ctx: &mut Ctx,
		fd: u32,
		offset: WasmPtr<FileSize>,
	) -> crate::Result<u16> {
		let fd_converted = Fd::try_from(fd).unwrap();
		let pos = bcfs!(self.bcfs.tell(fd_converted));
		self.memory_set_value(ctx, offset.offset(), pos)?;
		Ok(ErrNo::Success as u16)
	}

	pub fn fd_write(
		&mut self,
		ctx: &mut Ctx,
		fd: u32,
		iovs: WasmPtr<IoVec>,
		iovs_len: u32,
		nwritten: WasmPtr<u32>,
	) -> crate::Result<u16> {
		let fd_val = Fd::try_from(fd).unwrap();
		self.do_write(
			ctx,
			fd_val,
			iovs,
			Size::try_from(iovs_len).unwrap(),
			None,
			nwritten,
		)
	}

	pub fn path_create_directory(
		&mut self,
		_fd: u32,
		_path: WasmPtr<u8>,
		_path_len: u32,
	) -> crate::Result<u16> {
		Ok(ErrNo::NoSys as u16) // unimplemented(todo): vfs doesn't have directories
	}

	pub fn path_filestat_get(
		&mut self,
		_fd: u32,
		_lookup_flags: u32,
		_path: WasmPtr<u8>,
		_path_len: u32,
		_filestat_buf: WasmPtr<FileStat>,
	) -> crate::Result<u16> {
		Ok(ErrNo::NoSys as u16) // unimplemented(todo): vfs only allows statting open files
	}

	pub fn path_filestat_set_times(
		&mut self,
		_fd: u32,
		_lookup_flags: u32,
		_path: WasmPtr<u8>,
		_path_len: u32,
		_atime: u64,
		_mtime: u64,
		_fstflags: u16,
	) -> crate::Result<u16> {
		Ok(ErrNo::NoSys as u16) // unimplemented(todo): vfs doesn't track metadata
	}

	pub fn path_link(
		&mut self,
		_old_fd: u32,
		_old_lookup_flags: u32,
		_old_path: WasmPtr<u8>,
		_old_path_len: u32,
		_new_fd: u32,
		_new_path: WasmPtr<u8>,
		_new_path_len: u32,
	) -> crate::Result<u16> {
		Ok(ErrNo::NoSys as u16) // unimplemented(todo): vfs doesn't support links
	}

	pub fn path_open(
		&mut self,
		ctx: &mut Ctx,
		dir_fd: u32,
		_dir_flags: u32,
		path: WasmPtr<u8>,
		path_len: u32,
		open_flags: u16,
		_rights_base: u64,
		_rights_inheriting: u64,
		fd_flags: u16,
		p_fd: WasmPtr<Fd>,
	) -> crate::Result<u16> {
		let path = std::path::Path::new(
			// NB: immutable borrow of `self`
			match std::str::from_utf8(self.memory_get(ctx, path.offset(), path_len as usize)?) {
				Ok(path_str) => path_str,
				Err(_) => return Ok(ErrNo::Inval as u16),
			},
		);
		let path_ptr = path as *const std::path::Path;
		std::mem::forget(path);
		let path = unsafe { &*path_ptr }; // aliasing is safe as BCFS doesn't disturb linear memory

		// Convert from primatives to wasi_types
		let dir_fd_val = Fd::try_from(dir_fd).unwrap();
		let open_flags_val = OpenFlags::from_bits(open_flags).unwrap();
		let fd_flags_val = FdFlags::from_bits(fd_flags).unwrap();

		let fd = bcfs!(self // NB: mutable borrow of `self as PendingTransaction``
			.bcfs
			.open(dir_fd_val, path, open_flags_val, fd_flags_val));
		self.memory_set_value(ctx, p_fd.offset(), fd)?;
		Ok(ErrNo::Success as u16)
	}

	pub fn path_readlink(
		&mut self,
		_path: WasmPtr<u8>,
		_path_len: u32,
		_buf: WasmPtr<u8>,
		_buf_len: u32,
		_buf_used: WasmPtr<u32>,
	) -> crate::Result<u16> {
		Ok(ErrNo::NoSys as u16) // unimplemented(todo): vfs doesn't support links
	}

	pub fn path_remove_directory(
		&mut self,
		_fd: u32,
		_path: WasmPtr<u8>,
		_path_len: u32,
	) -> crate::Result<u16> {
		Ok(ErrNo::NoSys as u16) // unimplemented(todo): vfs doesn't have directories
	}

	pub fn path_rename(
		&mut self,
		_old_fd: u32,
		_old_lookup_flags: u32,
		_old_path: WasmPtr<u8>,
		_old_path_len: u32,
		_new_fd: u32,
		_new_path: WasmPtr<u8>,
		_new_path_len: u32,
	) -> crate::Result<u16> {
		Ok(ErrNo::NoSys as u16) // unimplemented(todo): vfs doesn't support rename
	}

	pub fn path_symlink(
		&mut self,
		_from_path: WasmPtr<u8>,
		_from_path_len: u32,
		_rel_fd: u32,
		_to_path: WasmPtr<u8>,
		_to_path_len: u32,
	) -> crate::Result<u16> {
		Ok(ErrNo::NoSys as u16) // unimplemented(todo): vfs doesn't support links
	}

	pub fn path_unlink_file(
		&mut self,
		ctx: &mut Ctx,
		dir_fd: u32,
		path: WasmPtr<u8, Array>,
		path_len: u32,
	) -> crate::Result<u16> {
		let path = std::path::Path::new(
			// NB: immutable borrow of `self`
			match std::str::from_utf8(self.memory_get(ctx, path.offset(), path_len as usize)?) {
				Ok(path_str) => path_str,
				Err(_) => return Ok(ErrNo::Inval as u16),
			},
		);
		let path_ptr = path as *const std::path::Path;
		std::mem::forget(path);
		let path = unsafe { &*path_ptr }; // aliasing is safe as BCFS doesn't disturb linear memory

		let dir_fd_val = Fd::try_from(dir_fd).unwrap();
		let prev_len = bcfs!(self.bcfs.unlink(dir_fd_val, path));

		self.ext
			.inc_sstore_clears(prev_len as u64)
			.map_err(|_| crate::runtime::Error::StorageUpdateError)?;
		Ok(ErrNo::Success as u16)
	}

	pub fn poll_oneoff(
		&mut self,
		_in: WasmPtr<u32>,
		_out: WasmPtr<u32>,
		_n_subs: u32,
	) -> crate::Result<u16> {
		Ok(ErrNo::Success as u16) // unimplemented(dontneed): nothing to poll
	}

	pub fn proc_exit(&mut self, ctx: &mut Ctx, rval: u32) -> crate::Result<u16> {
		self.should_persist = (rval == 0);
		Err(crate::runtime::Error::Return)
	}

	pub fn proc_raise(&mut self, _sig: u8) -> crate::Result<u16> {
		Ok(ErrNo::Success as u16) // unimplemented(dontneed): no controlling process
	}

	pub fn random_get(&mut self, _buf: WasmPtr<u8>, _buf_len: Size) -> crate::Result<u16> {
		Ok(ErrNo::NoSys as u16) // unimplemented(todo): seed prng with blockhash
	}

	pub fn sched_yield(&mut self) -> crate::Result<u16> {
		Ok(ErrNo::Success as u16) // unimplemented(dontneed): there's only one thread
	}
}

impl<'a> crate::Runtime<'a> {
	fn do_read(
		&mut self,
		ctx: &mut Ctx,
		fd: Fd,
		iovs: WasmPtr<IoVec, Array>,
		iovs_len: Size,
		offset: Option<FileSize>,
		nread: WasmPtr<Size, Array>,
	) -> crate::Result<u16> {
		let iovs: &[IoVec] = self.memory_get(ctx, iovs.offset(), iovs_len as usize)?;
		let mut ioslices = iovs
			.iter()
			.map(|iov| {
				let mem_slice = self.memory_get_mut::<u8>(ctx, iov.buf, iov.len as usize)?;
				let p = mem_slice.as_mut_ptr();
				std::mem::forget(mem_slice);
				// Launder the slice to get around borrow of `self` by `iovs` so that
				// it can be used by `bcfs` via `PendingTransaction`.
				Ok(std::io::IoSliceMut::new(unsafe {
					std::slice::from_raw_parts_mut(p, iov.len as usize)
				}))
			})
			.collect::<std::result::Result<Vec<_>, crate::runtime::Error>>()?;

		let nbytes = match offset {
			Some(offset) => bcfs!(self.bcfs.pread_vectored(fd, &mut ioslices, offset)),
			None => bcfs!(self.bcfs.read_vectored(fd, &mut ioslices)),
		};

		// Charge sload gas, scaled by number of bytes.
		let sload_gas = U256::from(self.schedule().sload_gas);
		let bytes_len = U256::from(nbytes);

		// gas <- ceiling(sload_gas * bytes_len / 32)
		// Cannot overflow as gas and len are converted from u64s.
		let mut gas = sload_gas * bytes_len / U256::from(32);
		if sload_gas * bytes_len % U256::from(32) != U256::from(0) {
			gas = gas + U256::from(1);
		}

		// Charge gas after checking for u64 overflow.
		if gas > U256::from(std::u64::MAX) {
			return Err(crate::runtime::Error::GasLimit);
		} else {
			self.adjusted_charge(|_| Some(gas.as_u64()))?;
		}

		self.memory_set_value(
			ctx,
			nread.offset(),
			nbytes,
			/* match nbytes.try_into() {
				Ok(nbytes) => nbytes,
				Err(_) => return Ok(ErrNo::MFile as u16),
			}, */
		)?;

		Ok(ErrNo::Success as u16)
	}

	fn do_write(
		&mut self,
		ctx: &mut Ctx,
		fd: Fd,
		iovs: WasmPtr<IoVec>,
		iovs_len: Size,
		offset: Option<FileSize>,
		nwritten: WasmPtr<u32>,
	) -> crate::Result<u16> {
		// TODO: refunds
		let iovs: &[IoVec] = self
			.memory_get_mut(ctx, iovs.offset(), iovs_len as usize)
			.unwrap();
		let ioslices = iovs
			.iter()
			.map(|iov| {
				let mem_slice = self
					.memory_get::<u8>(ctx, iov.buf, iov.len as usize)
					.unwrap();
				let p = mem_slice.as_ptr();
				std::mem::forget(mem_slice);
				// Launder the slice to get around borrow of `self` by `iovs` so that
				// it can be used by `bcfs` via `PendingTransaction`.
				Ok(std::io::IoSlice::new(unsafe {
					std::slice::from_raw_parts(p, iov.len as usize)
				}))
			})
			.collect::<std::result::Result<Vec<_>, crate::runtime::Error>>()?;

		#[cfg(debug_assertions)]
		{
			use std::io::Write;
			if u32::from(fd) == 1 {
				std::io::stdout().write_vectored(&ioslices).unwrap();
			} else if u32::from(fd) == 2 {
				std::io::stderr().write_vectored(&ioslices).unwrap();
			}
		}

		let prev_size = bcfs!(self.bcfs.filestat(fd)).file_size;

		let nbytes = match offset {
			Some(offset) => bcfs!(self.bcfs.pwrite_vectored(fd, &ioslices, offset)),
			None => bcfs!(self.bcfs.write_vectored(fd, &ioslices)),
		};

		let new_size = bcfs!(self.bcfs.filestat(fd)).file_size;
		self.storage_bytes_charge(
			new_size,
			new_size == prev_size, /* charge at the reset rate */
		)?;

		self.memory_set_value(ctx, nwritten.offset(), nbytes)?;

		Ok(ErrNo::Success as u16)
	}

	fn memory_get<T: Copy>(&self, ctx: &mut Ctx, offset: u32, count: usize) -> crate::Result<&[T]> {
		Ok(&*self.memory_get_mut(ctx, offset, count)?)
	}

	fn memory_get_mut<T: Copy>(
		&self,
		ctx: &mut Ctx,
		ptr: u32,
		count: usize,
	) -> crate::Result<&mut [T]> {
		let offset = ptr as usize;
		let mut mem_get_bytes = &ctx.memory(0).view()[offset..(offset + count)];

		let mem_slice =
			unsafe { std::mem::transmute::<&[std::cell::Cell<u8>], &[u8]>(mem_get_bytes) };

		Ok(unsafe { core::slice::from_raw_parts_mut(mem_slice.as_ptr() as *mut T, count) })
	}

	fn memory_set<T: Copy>(
		&self,
		ctx: &mut Ctx,
		ptr: u32,
		value: &[T],
	) -> crate::Result<WasmPtr<T>> {
		let offset = ptr as usize;
		let nbytes = value.len();

		let byte_buf = unsafe { std::slice::from_raw_parts(value.as_ptr() as *const u8, nbytes) };

		ctx.memory(0).view()[offset..(offset + nbytes)]
			.iter()
			.zip(byte_buf.iter())
			.for_each(|(cell, v)| cell.set(*v));

		Ok(WasmPtr::new(ptr + nbytes as u32))
	}

	fn memory_set_value<T: Copy>(
		&mut self,
		ctx: &mut Ctx,
		ptr: u32,
		value: T,
	) -> crate::Result<()> {
		let t_size = std::mem::size_of::<T>();
		let offset = ptr as usize;
		unsafe {
			let byte_buf: &[u8] =
				std::slice::from_raw_parts(&value as *const _ as *const u8, t_size);
			ctx.memory(0).view()[offset..(offset + t_size)]
				.iter()
				.zip(byte_buf.iter())
				.for_each(|(cell, v)| cell.set(*v));
		}
		Ok(())
	}
}
