use byteorder::{ByteOrder, BigEndian};
use serde_json::Value;
use std::sync::Arc;

/// 4-byte prefix prepended to data field indicating header
const HEADER_PREFIX: &'static [u8; 4] = b"\0sis";

pub const KEY_CONFIDENTIAL: &str = "confidential";
pub const KEY_EXPIRY: &str = "expiry";

#[derive(Debug, Clone)]
pub struct ContractHeader {
	pub length: usize,
	pub version: usize,
	pub value: Value,
	pub confidential: bool,
	pub expiry: Option<u64>,
	pub code: Arc<Vec<u8>>,
}

impl ContractHeader {
	pub fn extract_from_data(data: &[u8]) -> Result<Option<Self>, String> {
		// check for prefix
		if !has_header_prefix(data) {
			return Ok(None);
		}

		// strip prefix
		let data = &data[HEADER_PREFIX.len()..];

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

		// read version (2 bytes, big-endian)
		if length < 2 || data.len() < 2 {
			return Err("Invalid header version".to_string());
		}
		let version = BigEndian::read_u16(&data[..2]) as usize;
		let contents_length = length - 2;
		let data = &data[2..];

		// parse JSON contents
		let value: Value = match serde_json::from_slice(&data[..contents_length]) {
			Ok(val) => val,
			Err(e) => return Err("Malformed header".to_string()),
		};

		// parse expiry and confidential flag
		let expiry = match value[KEY_EXPIRY] {
			Value::Null => None,
			Value::Number(ref n) => {
				if n.is_u64() {
					n.as_u64()
				} else {
					return Err("Expiry must be an integer".to_string());
				}
			}
			_ => return Err("Expiry must be an integer".to_string()),
		};
		let confidential = match value[KEY_CONFIDENTIAL] {
			Value::Null => false,
			Value::Bool(b) => b,
			_ => return Err("Confidential must be a boolean".to_string()),
		};

		// the actual bytecode
		let code = data[contents_length..].to_vec();

		Ok(Some(Self {
			length,
			version,
			value,
			confidential,
			expiry,
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

	fn make_data_payload(header_json: Value) -> Vec<u8> {
		// start with header prefix
		let mut data = ElasticArray128::from_slice(&HEADER_PREFIX[..]);

		// contents (JSON)
		let contents = header_json.to_string().into_bytes();

		// header length (version + contents)
		let mut length = [0u8; 2];
		BigEndian::write_u16(&mut length, (contents.len() + 2) as u16);

		// header version
		let mut version = [0u8; 2];
		BigEndian::write_u16(&mut version, 1 as u16);

		// append header length, version and contents
		data.append_slice(&length);
		data.append_slice(&version);
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
		}));

		// extract header from slice
		let header = ContractHeader::extract_from_data(&data).unwrap().unwrap();

		// check fields
		assert_eq!(header.confidential, true);
		assert_eq!(header.expiry, Some(1577836800));
		assert_eq!(header.code, Arc::new("contract code".as_bytes().to_vec()));
	}

	#[test]
	fn test_no_header() {
		let data = b"data without a header";

		let header = ContractHeader::extract_from_data(&data[..]).expect("No header");

		assert!(header.is_none());
	}

	#[test]
	fn test_invalid_encoding() {
		// invalid length
		let data = b"\0sis\xff";
		let result = ContractHeader::extract_from_data(&data[..]);
		assert!(result.is_err());

		// data too short
		let data = b"\0sis\0\x01";
		let result = ContractHeader::extract_from_data(&data[..]);
		assert!(result.is_err());

		// malformed JSON
		let data = b"\0sis\0\x05\0\x01\xff\xff\xff";
		let result = ContractHeader::extract_from_data(&data[..]);
		assert!(result.is_err());
	}

	#[test]
	fn test_invalid_values() {
		// create a header with incorrect types
		let data = make_data_payload(json!({
			"confidential": "true",
			"expiry": "1577836800",
		}));

		let result = ContractHeader::extract_from_data(&data);
		assert!(result.is_err());
	}
}
