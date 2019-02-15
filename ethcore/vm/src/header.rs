use byteorder::{ByteOrder, BigEndian};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

/// 4-byte prefix prepended to contract code indicating header
const HEADER_PREFIX: &'static [u8; 4] = b"\0sis";

#[derive(Debug, Clone)]
pub struct ContractHeader {
	/// Header version.
	pub version: usize,
	/// Flag indicating whether contract is confidential.
	pub confidential: bool,
	/// Expiration timestamp for contract's storage (None if unspecified).
	pub expiry: Option<u64>,
	/// Raw bytes of header, to be prepended to stored bytecode.
	pub raw_header: Vec<u8>,
	/// Copy of the contract code with header removed.
	pub code: Arc<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderJson {
	confidential: Option<bool>,
	expiry: Option<u64>,
}

impl ContractHeader {
	pub fn extract_from_code(raw_code: &[u8]) -> Result<Option<Self>, String> {
		// check for prefix
		if !has_header_prefix(raw_code) {
			return Ok(None);
		}

		// strip prefix
		let data = &raw_code[HEADER_PREFIX.len()..];

		// read version (2 bytes, big-endian)
		if data.len() < 2 {
			return Err("Invalid header version".to_string());
		}
		let version = BigEndian::read_u16(&data[..2]) as usize;
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
		let h: HeaderJson = match serde_json::from_slice(&data[..length]) {
			Ok(val) => val,
			Err(e) => return Err("Malformed header".to_string()),
		};

		// split the raw code into header and bytecode
		let header_len = HEADER_PREFIX.len() + 4 + length;
		let raw_header = raw_code[0..header_len].to_vec();
		let code = raw_code[header_len..].to_vec();

		Ok(Some(Self {
			version,
			confidential: h.confidential.unwrap_or(false),
			expiry: h.expiry,
			raw_header,
			code: Arc::new(code),
		}))
	}
}

pub fn has_header_prefix(data: &[u8]) -> bool {
	if data.len() < HEADER_PREFIX.len() {
		return false;
	}
	let prefix = &data[..HEADER_PREFIX.len()];
	return prefix == HEADER_PREFIX;
}

#[cfg(test)]
mod tests {
	use super::*;
	use elastic_array::ElasticArray128;

	fn make_data_payload(json_str: String) -> Vec<u8> {
		// start with header prefix
		let mut data = ElasticArray128::from_slice(&HEADER_PREFIX[..]);

		// contents (JSON)
		let contents = json_str.into_bytes();

		// header version
		let mut version = [0u8; 2];
		BigEndian::write_u16(&mut version, 1 as u16);

		// header contents length
		let mut length = [0u8; 2];
		BigEndian::write_u16(&mut length, contents.len() as u16);

		// append header length, version and contents
		data.append_slice(&version);
		data.append_slice(&length);
		data.append_slice(&contents);

		// append some dummy body data
		data.append_slice(b"contract code");

		data.into_vec()
	}

	#[test]
	fn test_valid_header() {
		let data = make_data_payload(json!({
			"confidential": true,
			"expiry": 1577836800,
		}).to_string());

		// extract header from slice
		let header = ContractHeader::extract_from_code(&data).unwrap().unwrap();

		// check fields
		assert_eq!(header.confidential, true);
		assert_eq!(header.expiry, Some(1577836800));
		assert_eq!(header.code, Arc::new("contract code".as_bytes().to_vec()));
	}

	#[test]
	fn test_confidential_only() {
		let data = make_data_payload(json!({
			"confidential": true,
		}).to_string());

		// extract header from slice
		let header = ContractHeader::extract_from_code(&data).unwrap().unwrap();

		// check fields
		assert_eq!(header.confidential, true);
		assert_eq!(header.expiry, None);
	}

	#[test]
	fn test_expiry_only() {
		let data = make_data_payload(json!({
			"expiry": 1577836800,
		}).to_string());

		// extract header from slice
		let header = ContractHeader::extract_from_code(&data).unwrap().unwrap();

		// check fields
		assert_eq!(header.confidential, false);
		assert_eq!(header.expiry, Some(1577836800));
	}

	#[test]
	fn test_invalid_key() {
		let data = make_data_payload(json!({
			"expiry": 1577836800,
			"unknown": "something",
			"blah": "blah",
		}).to_string());

		let result = ContractHeader::extract_from_code(&data);
		assert!(result.is_err());
	}

	#[test]
	fn test_duplicate_key() {
		let data = make_data_payload(
			"{\"expiry\":1577836800,\"confidential\":true,\"expiry\":1577836801}"
			.to_string());

		let result = ContractHeader::extract_from_code(&data);
		assert!(result.is_err());
	}

	#[test]
	fn test_invalid_json() {
		let data = make_data_payload(json!("expiry").to_string());

		let result = ContractHeader::extract_from_code(&data);
		assert!(result.is_err());
	}

	#[test]
	fn test_no_header() {
		let data = b"data without a header";

		let header = ContractHeader::extract_from_code(&data[..]).expect("No header");
		assert!(header.is_none());
	}

	#[test]
	fn test_invalid_encoding() {
		// invalid length
		let data = b"\0sis\0\x01\xff";
		let result = ContractHeader::extract_from_code(&data[..]);
		assert!(result.is_err());

		// data too short
		let data = b"\0sis\0\x01\0\x01";
		let result = ContractHeader::extract_from_code(&data[..]);
		assert!(result.is_err());

		// malformed JSON
		let data = b"\0sis\0\x01\0\x03\xff\xff\xff";
		let result = ContractHeader::extract_from_code(&data[..]);
		assert!(result.is_err());
	}

	#[test]
	fn test_invalid_values() {
		// create a header with incorrect confidential type
		let invalid_confidential = make_data_payload(json!({
			"confidential": "true",
			"expiry": 1577836800,
		}).to_string());

		let result = ContractHeader::extract_from_code(&invalid_confidential[..]);
		assert!(result.is_err());

		// create a header with incorrect expiry type
		let invalid_expiry = make_data_payload(json!({
			"confidential": true,
			"expiry": "1577836800",
		}).to_string());

		let result = ContractHeader::extract_from_code(&invalid_expiry[..]);
		assert!(result.is_err());
	}
}
