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

use hyper;
use parking_lot::Mutex;
use std::sync::{atomic, mpsc, Arc};
use std::{thread, time};

use fetch::{self, Abort, Fetch, Request, Url};
use futures::{self, future, Future};

pub struct FetchControl {
	sender: mpsc::Sender<()>,
	fetch: FakeFetch,
}

impl FetchControl {
	pub fn respond(self) {
		self.sender
			.send(())
			.expect("Fetch cannot be finished without sending a response at least once.");
	}

	pub fn wait_for_requests(&self, len: usize) {
		const MAX_TIMEOUT: time::Duration = time::Duration::from_millis(5000);
		const ATTEMPTS: u32 = 10;
		let mut attempts_left = ATTEMPTS;
		loop {
			let current = self.fetch.requested.lock().len();

			if current == len {
				break;
			} else if attempts_left == 0 {
				panic!(
					"Timeout reached when waiting for pending requests. Expected: {}, current: {}",
					len, current
				);
			} else {
				attempts_left -= 1;
				// Should we handle spurious timeouts better?
				thread::park_timeout(MAX_TIMEOUT / ATTEMPTS);
			}
		}
	}
}

#[derive(Clone, Default)]
pub struct FakeFetch {
	manual: Arc<Mutex<Option<mpsc::Receiver<()>>>>,
	response: Arc<Mutex<Option<&'static [u8]>>>,
	asserted: Arc<atomic::AtomicUsize>,
	requested: Arc<Mutex<Vec<String>>>,
}

impl FakeFetch {
	pub fn set_response(&self, data: &'static [u8]) {
		*self.response.lock() = Some(data);
	}

	pub fn manual(&self) -> FetchControl {
		assert!(
			self.manual.lock().is_none(),
			"Only one manual control may be active."
		);
		let (tx, rx) = mpsc::channel();
		*self.manual.lock() = Some(rx);

		FetchControl {
			sender: tx,
			fetch: self.clone(),
		}
	}

	pub fn assert_requested(&self, url: &str) {
		let requests = self.requested.lock();
		let idx = self.asserted.fetch_add(1, atomic::Ordering::SeqCst);

		assert_eq!(
			requests.get(idx),
			Some(&url.to_owned()),
			"Expected fetch from specific URL."
		);
	}

	pub fn assert_no_more_requests(&self) {
		let requests = self.requested.lock();
		let len = self.asserted.load(atomic::Ordering::SeqCst);
		assert_eq!(
			requests.len(),
			len,
			"Didn't expect any more requests, got: {:?}",
			&requests[len..]
		);
	}
}

impl Fetch for FakeFetch {
	type Result = Box<Future<Item = fetch::Response, Error = fetch::Error> + Send>;

	fn fetch(&self, request: Request, abort: fetch::Abort) -> Self::Result {
		let u = request.url().clone();
		self.requested.lock().push(u.as_str().into());
		let manual = self.manual.clone();
		let response = self.response.clone();

		let (tx, rx) = futures::oneshot();
		thread::spawn(move || {
			if let Some(rx) = manual.lock().take() {
				// wait for manual resume
				let _ = rx.recv();
			}
			let data = response.lock().take().unwrap_or(b"Some content");
			tx.send(fetch::Response::new(
				u,
				hyper::Response::new().with_body(data),
				abort,
			))
			.unwrap();
		});

		Box::new(rx.map_err(|_| fetch::Error::Aborted))
	}

	fn get(&self, url: &str, abort: Abort) -> Self::Result {
		let url: Url = match url.parse() {
			Ok(u) => u,
			Err(e) => return Box::new(future::err(e.into())),
		};
		self.fetch(Request::get(url), abort)
	}

	fn post(&self, url: &str, abort: Abort) -> Self::Result {
		let url: Url = match url.parse() {
			Ok(u) => u,
			Err(e) => return Box::new(future::err(e.into())),
		};
		self.fetch(Request::post(url), abort)
	}
}
