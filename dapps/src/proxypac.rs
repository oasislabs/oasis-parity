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

//! Serving ProxyPac file

use apps::HOME_PAGE;
use endpoint::{Endpoint, EndpointPath, Request, Response};
use futures::future;
use handlers::ContentHandler;
use hyper::mime;

pub struct ProxyPac {
	dapps_domain: String,
}

impl ProxyPac {
	pub fn boxed(dapps_domain: String) -> Box<Endpoint> {
		Box::new(ProxyPac { dapps_domain })
	}
}

impl Endpoint for ProxyPac {
	fn respond(&self, path: EndpointPath, _req: Request) -> Response {
		let ui = format!("{}:{}", path.host, path.port);

		let content = format!(
			r#"
function FindProxyForURL(url, host) {{
	if (shExpMatch(host, "{0}.{1}"))
	{{
		return "PROXY {4}";
	}}

	if (shExpMatch(host, "*.{1}"))
	{{
		return "PROXY {2}:{3}";
	}}

	return "DIRECT";
}}
"#,
			HOME_PAGE, self.dapps_domain, path.host, path.port, ui
		);

		Box::new(future::ok(
			ContentHandler::ok(content, mime::TEXT_JAVASCRIPT).into(),
		))
	}
}
