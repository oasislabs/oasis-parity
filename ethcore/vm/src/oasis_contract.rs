use byteorder::{BigEndian, ByteOrder};
use elastic_array::ElasticArray128;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

/// 4-byte prefix prepended to contract code indicating header
pub const OASIS_HEADER_PREFIX: &'static [u8; 4] = b"\0sis";

#[derive(Debug, Clone)]
pub struct OasisContract {
	/// Header version.
	pub header_version: usize,
	/// Flag indicating whether contract is confidential.
	pub salt_if_confidential: Option<Salt>,
	/// Expiration timestamp for contract's storage (None if unspecified).
	pub expiry: Option<u64>,
	/// Header, to be prepended to stored bytecode.
	pub header: Vec<u8>,
	/// Copy of the contract code with header removed.
	pub code: Arc<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
	salt_if_confidential: Option<Salt>,
	expiry: Option<u64>,
}

/// Given that the contract state subtrie is not currently checked against the root hash,
/// the salt exists to prevent a malicious worker from substituting the contract code for
/// another that writes confidential state to the (public) io trie).
/// In this way, the address specified by the sender becomes a MAC, and hence closes the
/// aforementioned side channel.
type Salt = [u8; 32];

impl OasisContract {
	pub fn from_code(raw_code: &[u8]) -> Result<Option<Self>, String> {
		// check for prefix
		if !has_header_prefix(raw_code) {
			return Ok(None);
		}

		// strip prefix
		let data = &raw_code[OASIS_HEADER_PREFIX.len()..];

		// read version (2 bytes, big-endian)
		if data.len() < 2 {
			return Err("Invalid header version".to_string());
		}
		let header_version = BigEndian::read_u16(&data[..2]) as usize;
		// only version 1 allowed
		if header_version != 1 {
			return Err("Invalid header version".to_string());
		}
		let data = &data[2..];

		// read length (2 bytes, big-endian)
		if data.len() < 2 {
			return Err("Invalid header length".to_string());
		}
		let length = BigEndian::read_u16(&data[..2]) as usize;
		let data = &data[2..];

		// check length
		if data.len() < length {
			return Err("Data too short".to_string());
		}

		// parse JSON
		let h: Header = match serde_json::from_slice(&data[..length]) {
			Ok(val) => val,
			Err(e) => return Err("Malformed header".to_string()),
		};

		// split the raw code into header and bytecode
		let header_len = OASIS_HEADER_PREFIX.len() + 4 + length;
		let raw_header = raw_code[0..header_len].to_vec();
		let code = raw_code[header_len..].to_vec();

		Ok(Some(Self {
			header_version,
			salt_if_confidential: h.salt_if_confidential,
			expiry: h.expiry,
			header: raw_header,
			code: Arc::new(code),
		}))
	}

	pub fn make_header(version: usize, json_str: String) -> Vec<u8> {
		// start with header prefix
		let mut data = ElasticArray128::from_slice(&OASIS_HEADER_PREFIX[..]);

		// contents (JSON)
		let contents = json_str.into_bytes();

		// header version
		let mut header_version = [0u8; 2];
		BigEndian::write_u16(&mut header_version, version as u16);

		// header contents length
		let mut length = [0u8; 2];
		BigEndian::write_u16(&mut length, contents.len() as u16);

		// append header length, version and contents
		data.append_slice(&header_version);
		data.append_slice(&length);
		data.append_slice(&contents);

		data.into_vec()
	}

	pub fn is_confidential(&self) -> bool {
		self.salt_if_confidential.is_some()
	}
}

fn has_header_prefix(data: &[u8]) -> bool {
	if data.len() < OASIS_HEADER_PREFIX.len() {
		return false;
	}
	let prefix = &data[..OASIS_HEADER_PREFIX.len()];
	return prefix == OASIS_HEADER_PREFIX;
}

#[cfg(test)]
mod tests {
	use super::*;
	use elastic_array::ElasticArray128;

	fn make_data_payload(version: usize, json_str: String) -> Vec<u8> {
		let mut data = OasisContract::make_header(version, json_str);
		// append some dummy body data
		data.append(&mut b"contract code".to_vec());
		data
	}

	#[test]
	fn test_valid_header() {
		let data = make_data_payload(
			1,
			json!({
				"salt_if_confidential": &[1u8; std::mem::size_of::<Salt>()],
				"expiry": 1577836800,
			})
			.to_string(),
		);

		let contract = OasisContract::from_code(&data).unwrap().unwrap();

		assert_eq!(contract.salt_if_confidential, Some([1u8; 32]));
		assert_eq!(contract.expiry, Some(1577836800));
		assert_eq!(contract.code, Arc::new("contract code".as_bytes().to_vec()));
	}

	#[test]
	fn test_confidential_only() {
		let data = make_data_payload(
			1,
			json!({
				"salt_if_confidential": &[2u8; std::mem::size_of::<Salt>()],
			})
			.to_string(),
		);

		let contract = OasisContract::from_code(&data).unwrap().unwrap();

		assert_eq!(contract.is_confidential(), true);
		assert_eq!(contract.expiry, None);
	}

	#[test]
	fn test_expiry_only() {
		let data = make_data_payload(
			1,
			json!({
				"expiry": 1577836800,
			})
			.to_string(),
		);

		let contract = OasisContract::from_code(&data).unwrap().unwrap();

		assert!(!contract.is_confidential());
		assert_eq!(contract.expiry, Some(1577836800));
	}

	#[test]
	fn test_invalid_version() {
		let data = make_data_payload(
			2,
			json!({
				"salt_if_confidential": null,
				"expiry": 1577836800,
			})
			.to_string(),
		);

		let result = OasisContract::from_code(&data);
		assert!(result.is_err());
	}

	#[test]
	fn test_invalid_key() {
		let data = make_data_payload(
			1,
			json!({
				"confidential": true,
			})
			.to_string(),
		);

		let result = OasisContract::from_code(&data);
		assert!(result.is_err());
	}

	#[test]
	fn test_stringified_salt() {
		let mut salt = [0u8; std::mem::size_of::<Salt>()];
		for i in 0..salt.len() {
			salt[i] = i as u8;
		}
		let salt_str = format!(
			"[{}]",
			salt.iter()
				.map(|i| i.to_string())
				.collect::<Vec<_>>()
				.join(",")
		);
		let data = make_data_payload(1, format!("{{\"salt_if_confidential\":{}}}", salt_str));

		let contract = OasisContract::from_code(&data).unwrap().unwrap();
		assert_eq!(contract.salt_if_confidential, Some(salt));
	}

	#[test]
	fn test_duplicate_key() {
		let data = make_data_payload(
			1,
			"{\"expiry\":1577836800,\"salt_if_confidential\":null,\"expiry\":1577836801}"
				.to_string(),
		);

		let result = OasisContract::from_code(&data);
		assert!(result.is_err());
	}

	#[test]
	fn test_invalid_json() {
		let data = make_data_payload(1, json!("expiry").to_string());

		let result = OasisContract::from_code(&data);
		assert!(result.is_err());
	}

	#[test]
	fn test_no_header() {
		let data = b"data without a header";

		let contract = OasisContract::from_code(&data[..]).expect("No header");
		assert!(contract.is_none());
	}

	#[test]
	fn test_invalid_encoding() {
		// invalid length
		let data = b"\0sis\0\x01\xff";
		let result = OasisContract::from_code(&data[..]);
		assert!(result.is_err());

		// data too short
		let data = b"\0sis\0\x01\0\x01";
		let result = OasisContract::from_code(&data[..]);
		assert!(result.is_err());

		// malformed JSON
		let data = b"\0sis\0\x01\0\x03\xff\xff\xff";
		let result = OasisContract::from_code(&data[..]);
		assert!(result.is_err());
	}

	#[test]
	fn test_invalid_values() {
		// create a header with incorrect confidential type
		let invalid_confidential = make_data_payload(
			1,
			json!({
				"salt_if_confidential": "0123456789abcdef",
				"expiry": 1577836800,
			})
			.to_string(),
		);

		let result = OasisContract::from_code(&invalid_confidential[..]);
		assert!(result.is_err());

		// create a header with incorrect expiry type
		let invalid_expiry = make_data_payload(
			1,
			json!({
				"salt_if_confidential": &[3u8; std::mem::size_of::<Salt>()],
				"expiry": "1577836800",
			})
			.to_string(),
		);

		let result = OasisContract::from_code(&invalid_expiry[..]);
		assert!(result.is_err());
	}
}
