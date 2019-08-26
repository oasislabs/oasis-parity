use std::convert::TryInto;
use std::io::{IoSlice, IoSliceMut};

use blockchain_traits::PendingTransaction as _;
use wasi_types::*;
use wasmi::P;

use crate::runtime::RNG_HASH_BYTES;
use crate::U256;

const ADDR_LEN_BYTES: usize = std::mem::size_of::<oasis_types::Address>();
const ADDR_CHARS: usize = ADDR_LEN_BYTES * 2; // two hex digits per byte

macro_rules! bcfs {
	( $self:ident . bcfs . $fn:ident ( $($args:expr),* )  ) => {
		// Unsafety is required because BCFS is mutably borrowed with `self`
		// but also takes a `PendingTransaction` which also happens to be `self.
		// This is okay because BCFS doesn't modify itself through `PendingTransaction`.
		match unsafe { &mut *$self.bcfs.get() }.$fn($self, $( $args ),* ) {
			Ok(result) => result,
			Err(errno) => return Ok(errno)
		}
	}
}

#[wasm_macros::wasm_exports]
impl<'a> crate::Runtime<'a> {
	// not part of wasi, but required by parity
	pub fn gas(&mut self, amount: u32) -> crate::Result<()> {
		if self.charge_gas(amount as u64) {
			Ok(())
		} else {
			Err(crate::runtime::Error::GasLimit.into())
		}
	}

	pub fn args_get(&mut self, _argv: P<P<u8>>, _argv_buf: P<u8>) -> crate::Result<ErrNo> {
		Ok(ErrNo::Success)
	}

	pub fn args_sizes_get(&mut self, argc: P<u32>, _argv_buf_size: P<u32>) -> crate::Result<ErrNo> {
		self.memory.set_value(argc, 0)?;
		Ok(ErrNo::Success)
	}

	pub fn clock_res_get(
		&mut self,
		clock_id: ClockId,
		resolution: P<Timestamp>,
	) -> crate::Result<ErrNo> {
		self.memory.set_value(
			resolution,
			match clock_id {
				ClockId::RealTime | ClockId::Monotonic => Timestamp::from_nanos(250 * 1_000_000),
				_ => return Ok(ErrNo::Inval),
			},
		)?;
		Ok(ErrNo::Success)
	}

	pub fn clock_time_get(
		&mut self,
		clock_id: ClockId,
		_precision: Timestamp,
		time: P<Timestamp>,
	) -> crate::Result<ErrNo> {
		match clock_id {
			ClockId::RealTime | ClockId::Monotonic => self
				.memory
				.set_value(time, Timestamp::from_sec(self.ext.env_info().timestamp))?,
			_ => return Ok(ErrNo::Inval),
		}
		Ok(ErrNo::Success)
	}

	pub fn environ_get(
		&mut self,
		environ: P<P<u8>>,
		mut environ_buf: P<u8>,
	) -> crate::Result<ErrNo> {
		let environs = self.memory.get_mut(environ, 4)?;
		environs[0] = environ_buf;
		environ_buf = self.memory.set(
			environ_buf,
			format!("ADDRESS={:x}\0", self.context.address).as_bytes(),
		)?;
		environs[1] = environ_buf;
		environ_buf = self.memory.set(
			environ_buf,
			format!("SENDER={:x}\0", self.context.sender).as_bytes(),
		)?;
		environs[2] = environ_buf;
		self.memory.set(
			environ_buf,
			format!("AAD={}\0", self.context.aad_str).as_bytes(),
		)?;
		environs[3] = environ_buf;
		self.memory.set(
			environ_buf,
			format!("VALUE={}\0", self.context.value_str).as_bytes(),
		)?;
		Ok(ErrNo::Success)
	}

	pub fn environ_sizes_get(
		&mut self,
		environ_count: P<u32>,
		environ_buf_size: P<u32>,
	) -> crate::Result<ErrNo> {
		self.memory.set_value(environ_count, 4u32)?; // sender, address, aad, value
		self.memory.set_value(
			environ_buf_size,
			#[rustfmt::skip] (
				"SENDER=".len() + ADDR_CHARS +
				"\0ADDRESS=".len() + ADDR_CHARS +
				"\0AAD=".len() + self.context.aad_str.len() +
				"\0VALUE=".len() + self.context.value_str.len() +
				"\0".len()
			) as u32,
		)?;
		Ok(ErrNo::Success)
	}

	pub fn fd_advise(
		&mut self,
		_fd: Fd,
		_offset: FileSize,
		_len: FileSize,
		_advice: Advice,
	) -> crate::Result<ErrNo> {
		// unimplemented(todo): advice is an optimization and can be ignored
		Ok(ErrNo::Success)
	}

	pub fn fd_allocate(
		&mut self,
		_fd: Fd,
		_offset: FileSize,
		_len: FileSize,
	) -> crate::Result<ErrNo> {
		// unimplemented(dontneed): storage is allocated on demand
		Ok(ErrNo::Success)
	}

	pub fn fd_close(&mut self, fd: Fd) -> crate::Result<ErrNo> {
		bcfs!(self.bcfs.close(fd));
		Ok(ErrNo::Success)
	}

	pub fn fd_datasync(&mut self, fd: Fd) -> crate::Result<ErrNo> {
		bcfs!(self.bcfs.flush(fd));
		Ok(ErrNo::Success)
	}

	pub fn fd_fdstat_get(&mut self, fd: Fd, buf: P<FdStat>) -> crate::Result<ErrNo> {
		let stats = bcfs!(self.bcfs.fdstat(fd));
		self.memory.set_value(buf, stats)?;
		Ok(ErrNo::Success)
	}

	pub fn fd_fdstat_set_flags(&mut self, _fd: Fd, _flags: FdFlags) -> crate::Result<ErrNo> {
		Ok(ErrNo::NotCapable)
	}

	pub fn fd_fdstat_set_rights(
		&mut self,
		_fd: Fd,
		_rights_base: Rights,
		_rights_inheriting: Rights,
	) -> crate::Result<ErrNo> {
		Ok(ErrNo::NotCapable)
	}

	pub fn fd_filestat_get(&mut self, fd: Fd, buf: P<FileStat>) -> crate::Result<ErrNo> {
		self.memory.set_value(buf, bcfs!(self.bcfs.filestat(fd)))?;
		Ok(ErrNo::Success)
	}

	pub fn fd_filestat_set_size(&mut self, _fd: Fd, _size: FileSize) -> crate::Result<ErrNo> {
		// unimplemented(dontneed): storage is immutable and allocated on demand
		Ok(ErrNo::Success)
	}

	pub fn fd_filestat_set_times(
		&mut self,
		_fd: Fd,
		_atime: Timestamp,
		_mtime: Timestamp,
		_flags: SetTimeFlags,
	) -> crate::Result<ErrNo> {
		// unimplemented(todo): vfs doesn't keep track of metadata
		Ok(ErrNo::NoSys)
	}

	pub fn fd_pread(
		&mut self,
		fd: Fd,
		iovs: P<IoVec>,
		iovs_len: Size,
		offset: FileSize,
		nread: P<Size>,
	) -> crate::Result<ErrNo> {
		self.do_read(fd, iovs, iovs_len, Some(offset), nread)
	}

	pub fn fd_prestat_dir_name(
		&mut self,
		fd: Fd,
		path_ptr: P<u8>,
		path_len: Size,
	) -> crate::Result<ErrNo> {
		let path_str = bcfs!(self.bcfs.prestat(fd)).to_str().unwrap();
		self.memory.set(path_ptr, path_str.as_bytes())?;
		self.memory.set_value(path_len, path_str.len())?;
		Ok(ErrNo::Success)
	}

	pub fn fd_prestat_get(&mut self, fd: Fd, buf: P<Prestat>) -> crate::Result<ErrNo> {
		let path_str = bcfs!(self.bcfs.prestat(fd)).to_str().unwrap();
		self.memory.set_value(
			buf,
			Prestat {
				resource_type: PreopenType::Dir {
					name_len: match path_str.len().try_into() {
						Ok(name_len) => name_len,
						Err(_) => return Ok(ErrNo::NameTooLong),
					},
				},
			},
		)?;
		Ok(ErrNo::Success)
	}

	pub fn fd_pwrite(
		&mut self,
		fd: Fd,
		iovs: P<IoVec>,
		iovs_len: Size,
		offset: FileSize,
		nwritten: P<Size>,
	) -> crate::Result<ErrNo> {
		self.do_write(fd, iovs, iovs_len, Some(offset), nwritten)
	}

	pub fn fd_read(
		&mut self,
		fd: Fd,
		iovs: P<IoVec>,
		iovs_len: Size,
		nread: P<Size>,
	) -> crate::Result<ErrNo> {
		self.do_read(fd, iovs, iovs_len, None, nread)
	}

	pub fn fd_readdir(
		&mut self,
		_fd: Fd,
		_buf: P<u8>,
		_buf_len: u32,
		_dircookie: DirCookie,
		_buf_used: P<u32>,
	) -> crate::Result<ErrNo> {
		Ok(ErrNo::NoSys) // unimplemented(todo): vfs doesn't have directories
	}

	pub fn fd_renumber(&mut self, from: Fd, to: Fd) -> crate::Result<ErrNo> {
		bcfs!(self.bcfs.renumber(from, to));
		Ok(ErrNo::Success)
	}

	pub fn fd_seek(
		&mut self,
		fd: Fd,
		offset: FileDelta,
		whence: Whence,
		new_offset: P<FileSize>,
	) -> crate::Result<ErrNo> {
		let new_pos = bcfs!(self.bcfs.seek(fd, offset, whence));
		self.memory.set_value(new_offset, new_pos)?;
		Ok(ErrNo::Success)
	}

	pub fn fd_sync(&mut self, fd: Fd) -> crate::Result<ErrNo> {
		self.fd_datasync(fd) // there's no metadata
	}

	pub fn fd_tell(&mut self, fd: Fd, offset: P<FileSize>) -> crate::Result<ErrNo> {
		let pos = bcfs!(self.bcfs.tell(fd));
		self.memory.set_value(offset, pos)?;
		Ok(ErrNo::Success)
	}

	pub fn fd_write(
		&mut self,
		fd: Fd,
		iovs: P<IoVec>,
		iovs_len: Size,
		nwritten: P<Size>,
	) -> crate::Result<ErrNo> {
		self.do_write(fd, iovs, iovs_len, None, nwritten)
	}

	pub fn path_create_directory(
		&mut self,
		_fd: Fd,
		_path: P<u8>,
		_path_len: u32,
	) -> crate::Result<ErrNo> {
		Ok(ErrNo::NoSys) // unimplemented(todo): vfs doesn't have directories
	}

	pub fn path_filestat_get(
		&mut self,
		_fd: Fd,
		_lookup_flags: LookupFlags,
		_path: P<u8>,
		_path_len: u32,
		_filestat_buf: P<FileStat>,
	) -> crate::Result<ErrNo> {
		Ok(ErrNo::NoSys) // unimplemented(todo): vfs only allows statting open files
	}

	pub fn path_filestat_set_times(
		&mut self,
		_fd: Fd,
		_lookup_flags: LookupFlags,
		_path: P<u8>,
		_path_len: u32,
		_atime: Timestamp,
		_mtime: Timestamp,
		_fstflags: SetTimeFlags,
	) -> crate::Result<ErrNo> {
		Ok(ErrNo::NoSys) // unimplemented(todo): vfs doesn't track metadata
	}

	pub fn path_link(
		&mut self,
		_old_fd: Fd,
		_old_lookup_flags: LookupFlags,
		_old_path: P<u8>,
		_old_path_len: u32,
		_new_fd: Fd,
		_new_path: P<u8>,
		_new_path_len: u32,
	) -> crate::Result<ErrNo> {
		Ok(ErrNo::NoSys) // unimplemented(todo): vfs doesn't support links
	}

	pub fn path_open(
		&mut self,
		dir_fd: Fd,
		_dir_flags: LookupFlags,
		path: P<u8>,
		path_len: u32,
		open_flags: OpenFlags,
		_rights_base: Rights,
		_rights_inheriting: Rights,
		fd_flags: FdFlags,
		p_fd: P<Fd>,
	) -> crate::Result<ErrNo> {
		let path = std::path::Path::new(
			// NB: immutable borrow of `self`
			match std::str::from_utf8(self.memory.get(path, path_len as usize)?) {
				Ok(path_str) => path_str,
				Err(_) => return Ok(ErrNo::Inval),
			},
		);
		let path_ptr = path as *const std::path::Path;
		std::mem::forget(path);
		let path = unsafe { &*path_ptr }; // aliasing is safe as BCFS doesn't disturb linear memory
		let fd = bcfs!(self // NB: mutable borrow of `self as PendingTransaction``
			.bcfs
			.open(dir_fd, path, open_flags, fd_flags));
		self.memory.set_value(p_fd, fd)?;
		Ok(ErrNo::Success)
	}

	pub fn path_readlink(
		&mut self,
		_path: P<u8>,
		_path_len: u32,
		_buf: P<u8>,
		_buf_len: u32,
		_buf_used: P<u32>,
	) -> crate::Result<ErrNo> {
		Ok(ErrNo::NoSys) // unimplemented(todo): vfs doesn't support links
	}

	pub fn path_remove_directory(
		&mut self,
		_fd: Fd,
		_path: P<u8>,
		_path_len: u32,
	) -> crate::Result<ErrNo> {
		Ok(ErrNo::NoSys) // unimplemented(todo): vfs doesn't have directories
	}

	pub fn path_rename(
		&mut self,
		_old_fd: Fd,
		_old_lookup_flags: LookupFlags,
		_old_path: P<u8>,
		_old_path_len: u32,
		_new_fd: Fd,
		_new_path: P<u8>,
		_new_path_len: u32,
	) -> crate::Result<ErrNo> {
		Ok(ErrNo::NoSys) // unimplemented(todo): vfs doesn't support rename
	}

	pub fn path_symlink(
		&mut self,
		_from_path: P<u8>,
		_from_path_len: u32,
		_rel_fd: Fd,
		_to_path: P<u8>,
		_to_path_len: u32,
	) -> crate::Result<ErrNo> {
		Ok(ErrNo::NoSys) // unimplemented(todo): vfs doesn't support links
	}

	pub fn path_unlink_file(
		&mut self,
		dir_fd: Fd,
		path: P<u8>,
		path_len: u32,
	) -> crate::Result<ErrNo> {
		let path = std::path::Path::new(
			// NB: immutable borrow of `self`
			match std::str::from_utf8(self.memory.get(path, path_len as usize)?) {
				Ok(path_str) => path_str,
				Err(_) => return Ok(ErrNo::Inval),
			},
		);
		let path_ptr = path as *const std::path::Path;
		std::mem::forget(path);
		let path = unsafe { &*path_ptr }; // aliasing is safe as BCFS doesn't disturb linear memory
		let prev_len = bcfs!(self.bcfs.unlink(dir_fd, path));
		self.ext
			.inc_sstore_clears(prev_len as u64)
			.map_err(|_| crate::runtime::Error::StorageUpdateError)?;
		Ok(ErrNo::Success)
	}

	pub fn poll_oneoff(&mut self, _in: P<u32>, _out: P<u32>, _n_subs: u32) -> crate::Result<ErrNo> {
		Ok(ErrNo::Success) // unimplemented(dontneed): nothing to poll
	}

	pub fn proc_exit(&mut self, rval: u32) -> crate::Result<ErrNo> {
		self.should_revert = rval != 0;
		Err(crate::runtime::Error::Return)
	}

	pub fn proc_raise(&mut self, _sig: Signal) -> crate::Result<ErrNo> {
		Ok(ErrNo::Success) // unimplemented(dontneed): no controlling process
	}

	pub fn random_get(&mut self, buf: P<u8>, buf_len: Size) -> crate::Result<ErrNo> {
		let buf_len = buf_len as usize;
		let rng_buf_blocks = (buf_len + RNG_HASH_BYTES) / RNG_HASH_BYTES;
		let rng_buf_len = rng_buf_blocks * RNG_HASH_BYTES;
		let mut rng_buf = Vec::with_capacity(rng_buf_len);
		unsafe { rng_buf.set_len(rng_buf_len) };
		self.rng.generate_to_slice(&mut rng_buf, None);
		self.memory
			.get_mut(buf, buf_len)?
			.copy_from_slice(&rng_buf[..buf_len]);
		Ok(ErrNo::Success)
	}

	pub fn sched_yield(&mut self) -> crate::Result<ErrNo> {
		Ok(ErrNo::Success) // unimplemented(dontneed): there's only one thread
	}

	pub fn blockchain_transact(
		&mut self,
		p_callee_addr: P<u8>,
		value: u64,
		p_input: P<u8>,
		input_len: u64,
		p_fd: P<Fd>,
	) -> crate::Result<ErrNo> {
		let callee_addr: oasis_types::Address = self.memory.get_value(p_callee_addr)?;

		let input_len = input_len as usize;
		let input_ptr = self.memory.get::<_, u8>(p_input, input_len)?.as_ptr();
		std::mem::forget(input_ptr);
		let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len) };
		// ^ Mutable borrow needed for `self.transact`, but transact doesn't touch linear memory.

		let receipt = self.transact(callee_addr, value, input);
		let fd = bcfs!(self.bcfs.tempfile());
		bcfs!(self.bcfs.pwrite_vectored(
			fd,
			&[IoSlice::new(receipt.output())],
			0 /* offset */
		));
		self.memory.set_value(p_fd, fd)?;

		Ok(if receipt.reverted() {
			ErrNo::ConnAborted
		} else {
			ErrNo::Success
		})
	}
}

impl<'a> crate::Runtime<'a> {
	fn do_read(
		&mut self,
		fd: Fd,
		iovs: P<IoVec>,
		iovs_len: Size,
		offset: Option<FileSize>,
		nread: P<Size>,
	) -> crate::Result<ErrNo> {
		let iovs: &[IoVec] = self.memory.get(iovs, iovs_len as usize)?;
		let mut ioslices = iovs
			.iter()
			.map(|iov| {
				let mem_slice = self.memory.get_mut::<_, u8>(iov.buf, iov.len as usize)?;
				let p = mem_slice.as_mut_ptr();
				std::mem::forget(mem_slice);
				// Launder the slice to get around borrow of `self` by `iovs` so that
				// it can be used by `bcfs` via `PendingTransaction`.
				Ok(IoSliceMut::new(unsafe {
					std::slice::from_raw_parts_mut(p, iov.len as usize)
				}))
			})
			.collect::<std::result::Result<Vec<_>, wasmi::Error>>()?;

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

		self.memory.set_value(
			nread,
			match nbytes.try_into() {
				Ok(nbytes) => nbytes,
				Err(_) => return Ok(ErrNo::MFile),
			},
		)?;

		Ok(ErrNo::Success)
	}

	fn do_write(
		&mut self,
		fd: Fd,
		iovs: P<IoVec>,
		iovs_len: Size,
		offset: Option<FileSize>,
		nwritten: P<Size>,
	) -> crate::Result<ErrNo> {
		// TODO: refunds
		let iovs: &[IoVec] = self.memory.get(iovs, iovs_len as usize)?;
		let ioslices = iovs
			.iter()
			.map(|iov| {
				let mem_slice = self.memory.get::<_, u8>(iov.buf, iov.len as usize)?;
				let p = mem_slice.as_ptr();
				std::mem::forget(mem_slice);
				// Launder the slice to get around borrow of `self` by `iovs` so that
				// it can be used by `bcfs` via `PendingTransaction`.
				Ok(IoSlice::new(unsafe {
					std::slice::from_raw_parts(p, iov.len as usize)
				}))
			})
			.collect::<std::result::Result<Vec<_>, wasmi::Error>>()?;

		#[cfg(feature = "wasi-debug-stdio")]
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

		self.memory.set_value(
			nwritten,
			match nbytes.try_into() {
				Ok(nbytes) => nbytes,
				Err(_) => return Ok(ErrNo::MFile),
			},
		)?;

		Ok(ErrNo::Success)
	}
}
