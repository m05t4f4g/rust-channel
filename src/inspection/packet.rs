use std::collections::HashMap;
use crate::config::FixParserConfig;

// Define all the necessary types at the top level
#[derive(Debug, Clone, PartialEq)]
pub struct PacketHeader {
    pub msg_type: String,
    pub msg_seq: u32,
    pub timestamp: u64,
    pub sender_comp_id: Option<String>,
    pub target_comp_id: Option<String>,
    pub sending_time: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PacketTrailer {
    pub checksum: u32,
    pub signature: Option<String>,
    pub body_length: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedPacket {
    pub header: Option<PacketHeader>,
    pub payload: Vec<u8>,
    pub trailer: Option<PacketTrailer>,
    pub fix_fields: Option<HashMap<u32, String>>,
    pub inspected_tags: Option<HashMap<u32, String>>,
}

#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error("Packet too short: expected at least {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },
    #[error("Packet too long: expected at most {expected} bytes, got {actual}")]
    TooLong { expected: usize, actual: usize },
    #[error("Checksum validation failed")]
    ChecksumFailed,
    #[error("FIX protocol error: {0}")]
    FixError(String),
    #[error("Invalid packet structure")]
    InvalidStructure,
}

pub trait ProtocolParser: Send + Sync {
    fn parse_packet(&self, data: &[u8]) -> Result<ParsedPacket, PacketError>;
    fn validate_checksum(&self, data: &[u8]) -> bool;
    fn extract_msg_type(&self, data: &[u8]) -> Option<String>;
}

// Binary Parser implementation
pub struct BinaryParser {
    header_size: usize,
    footer_size: usize,
}

impl BinaryParser {
    pub fn new(header_size: usize, footer_size: usize) -> Self {
        Self {
            header_size,
            footer_size,
        }
    }
}

impl ProtocolParser for BinaryParser {
    fn parse_packet(&self, data: &[u8]) -> Result<ParsedPacket, PacketError> {
        if data.len() < self.header_size + self.footer_size {
            return Err(PacketError::TooShort {
                expected: self.header_size + self.footer_size,
                actual: data.len(),
            });
        }

        let payload = data[self.header_size..data.len() - self.footer_size].to_vec();

        Ok(ParsedPacket {
            header: None,
            payload,
            trailer: None,
            fix_fields: None,
            inspected_tags: None,
        })
    }

    fn validate_checksum(&self, _data: &[u8]) -> bool {
        true
    }

    fn extract_msg_type(&self, _data: &[u8]) -> Option<String> {
        Some("BINARY".to_string())
    }
}

// FixParser implementation
#[derive(Clone)]
pub struct FixParser {
    pub config: FixParserConfig,
}

impl FixParser {
    pub fn new(config: FixParserConfig) -> Self {
        Self { config }
    }

    pub fn with_default_config() -> Self {
        Self {
            config: FixParserConfig::default(),
        }
    }

    /// Parse FIX message fields (tag=value| format)
    pub fn parse_fix_fields(&self, data: &[u8]) -> Result<HashMap<u32, String>, PacketError> {
        let mut fields = HashMap::new();
        let mut remaining = data;

        while !remaining.is_empty() {
            // Find the delimiter between tag and value
            let delimiter_pos = remaining.iter().position(|&b| b == b'=');
            if delimiter_pos.is_none() {
                break;
            }

            let (tag_bytes, after_delimiter) = remaining.split_at(delimiter_pos.unwrap());
            let after_delimiter = &after_delimiter[1..]; // Skip the '='

            // Parse tag
            let tag_str = std::str::from_utf8(tag_bytes)
                .map_err(|e| PacketError::FixError(format!("Invalid tag encoding: {}", e)))?;
            let tag = tag_str.parse::<u32>()
                .map_err(|e| PacketError::FixError(format!("Invalid tag format: {}", e)))?;

            // Find the SOH delimiter (0x01) or end of data
            let value_end_pos = after_delimiter.iter().position(|&b| b == 0x01)
                .unwrap_or(after_delimiter.len());

            let (value_bytes, next_field) = after_delimiter.split_at(value_end_pos);

            // Parse value
            let value = std::str::from_utf8(value_bytes)
                .map_err(|e| PacketError::FixError(format!("Invalid value encoding: {}", e)))?
                .to_string();

            fields.insert(tag, value);

            // Move to next field (skip SOH if present)
            remaining = if !next_field.is_empty() && next_field[0] == 0x01 {
                &next_field[1..]
            } else {
                next_field
            };
        }

        Ok(fields)
    }

    /// Extract only the tags specified in config for inspection
    pub fn extract_inspected_tags(&self, fields: &HashMap<u32, String>) -> HashMap<u32, String> {
        let mut inspected = HashMap::new();

        for &tag in &self.config.inspect_tags {
            if let Some(value) = fields.get(&tag) {
                inspected.insert(tag, value.clone());
            }
        }

        inspected
    }

    /// Extract specific field from FIX message
    fn get_fix_field(fields: &HashMap<u32, String>, tag: u32) -> Option<&String> {
        fields.get(&tag)
    }

    /// Parse FIX message type from fields
    fn parse_msg_type(fields: &HashMap<u32, String>) -> Option<String> {
        Self::get_fix_field(fields, 35).map(|s| s.to_string())
    }

    /// Parse FIX message sequence number
    fn parse_msg_seq_num(fields: &HashMap<u32, String>) -> u32 {
        Self::get_fix_field(fields, 34)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0)
    }

    /// Parse FIX body length
    fn parse_body_length(fields: &HashMap<u32, String>) -> Option<u32> {
        Self::get_fix_field(fields, 9).and_then(|s| s.parse::<u32>().ok())
    }

    /// Parse sender comp ID
    fn parse_sender_comp_id(fields: &HashMap<u32, String>) -> Option<String> {
        Self::get_fix_field(fields, 49).map(|s| s.to_string())
    }

    /// Parse target comp ID
    fn parse_target_comp_id(fields: &HashMap<u32, String>) -> Option<String> {
        Self::get_fix_field(fields, 56).map(|s| s.to_string())
    }

    /// Parse sending time
    fn parse_sending_time(fields: &HashMap<u32, String>) -> Option<String> {
        Self::get_fix_field(fields, 52).map(|s| s.to_string())
    }

    /// Parse FIX checksum (tag 10)
    fn parse_checksum(fields: &HashMap<u32, String>) -> Option<u32> {
        Self::get_fix_field(fields, 10)
            .and_then(|s| u32::from_str_radix(s, 10).ok())
    }

    /// Calculate FIX checksum
    pub fn calculate_fix_checksum(data: &[u8]) -> u32 {
        data.iter().fold(0u32, |acc, &b| acc + b as u32) % 256
    }

    /// Validate FIX message structure based on config
    pub fn validate_fix_structure(&self, fields: &HashMap<u32, String>) -> Result<(), PacketError> {
        if !self.config.validate_structure {
            return Ok(());
        }

        // Check for required FIX fields
        for &required_tag in &self.config.required_tags {
            if !fields.contains_key(&required_tag) {
                return Err(PacketError::FixError(
                    format!("Missing required tag: {}", required_tag)
                ));
            }
        }

        Ok(())
    }

    /// Get tag name for logging (common FIX tags)
    fn get_tag_name(tag: u32) -> &'static str {
        match tag {
            8 => "BeginString",
            9 => "BodyLength",
            35 => "MsgType",
            34 => "MsgSeqNum",
            49 => "SenderCompID",
            56 => "TargetCompID",
            52 => "SendingTime",
            10 => "CheckSum",
            1 => "Account",
            11 => "ClOrdID",
            14 => "CumQty",
            17 => "ExecID",
            20 => "ExecTransType",
            31 => "LastPx",
            32 => "LastQty",
            37 => "OrderID",
            38 => "OrderQty",
            39 => "OrdStatus",
            40 => "OrdType",
            44 => "Price",
            54 => "Side",
            55 => "Symbol",
            58 => "Text",
            59 => "TimeInForce",
            60 => "TransactTime",
            150 => "ExecType",
            151 => "LeavesQty",
            _ => "Unknown",
        }
    }

    /// Log inspected tags for debugging
    pub fn log_inspected_tags(&self, inspected_tags: &HashMap<u32, String>) {
        if inspected_tags.is_empty() {
            return;
        }

        let mut tag_info = Vec::new();
        for (tag, value) in inspected_tags {
            let tag_name = Self::get_tag_name(*tag);
            tag_info.push(format!("{}({})={}", tag_name, tag, value));
        }

        // Use tracing directly since we can't guarantee log_debug macro availability here
        tracing::debug!(
            fix_tags = ?tag_info,
            "🔍 FIX tags inspected"
        );
    }
}

impl ProtocolParser for FixParser {
    fn parse_packet(&self, data: &[u8]) -> Result<ParsedPacket, PacketError> {
        if !self.config.enabled {
            return Err(PacketError::FixError("FIX parser disabled".to_string()));
        }

        if data.len() < 20 {
            return Err(PacketError::TooShort {
                expected: 20,
                actual: data.len(),
            });
        }

        // Parse FIX fields
        let fix_fields = self.parse_fix_fields(data)?;

        // Validate FIX structure
        self.validate_fix_structure(&fix_fields)?;

        // Extract only the tags we want to inspect
        let inspected_tags = self.extract_inspected_tags(&fix_fields);

        // Log inspected tags for debugging
        self.log_inspected_tags(&inspected_tags);

        // Extract message type
        let msg_type = Self::parse_msg_type(&fix_fields)
            .ok_or_else(|| PacketError::FixError("Could not parse MsgType".to_string()))?;

        // Extract sequence number
        let msg_seq = Self::parse_msg_seq_num(&fix_fields);

        // Extract header information
        let sender_comp_id = Self::parse_sender_comp_id(&fix_fields);
        let target_comp_id = Self::parse_target_comp_id(&fix_fields);
        let sending_time = Self::parse_sending_time(&fix_fields);

        // Extract body length
        let body_length = Self::parse_body_length(&fix_fields);

        // Extract and validate checksum if enabled
        let expected_checksum = if self.config.validate_checksum {
            Self::parse_checksum(&fix_fields)
                .ok_or_else(|| PacketError::FixError("Could not parse CheckSum".to_string()))?
        } else {
            0
        };

        if self.config.validate_checksum {
            let calculated_checksum = Self::calculate_fix_checksum(data);
            if expected_checksum != calculated_checksum {
                return Err(PacketError::ChecksumFailed);
            }
        }

        let header = PacketHeader {
            msg_type,
            msg_seq,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            sender_comp_id,
            target_comp_id,
            sending_time,
        };

        let payload = data.to_vec();

        let trailer = PacketTrailer {
            checksum: expected_checksum,
            signature: None,
            body_length,
        };

        Ok(ParsedPacket {
            header: Some(header),
            payload,
            trailer: Some(trailer),
            fix_fields: Some(fix_fields),
            inspected_tags: Some(inspected_tags),
        })
    }

    fn validate_checksum(&self, data: &[u8]) -> bool {
        if !self.config.validate_checksum {
            return true;
        }

        if let Ok(fields) = self.parse_fix_fields(data) {
            if let Some(expected_checksum) = Self::parse_checksum(&fields) {
                let calculated_checksum = Self::calculate_fix_checksum(data);
                return expected_checksum == calculated_checksum;
            }
        }
        false
    }

    fn extract_msg_type(&self, data: &[u8]) -> Option<String> {
        if !self.config.enabled {
            return None;
        }

        if data.len() < 10 {
            return None;
        }

        if !data.starts_with(b"8=FIX") {
            return None;
        }

        let mut remaining = data;
        while !remaining.is_empty() {
            if remaining.starts_with(b"35=") {
                let after_tag = &remaining[3..];
                let value_end = after_tag.iter()
                    .position(|&b| b == 0x01)
                    .unwrap_or(after_tag.len());

                if value_end > 0 {
                    let msg_type_bytes = &after_tag[..value_end];
                    return Some(String::from_utf8_lossy(msg_type_bytes).to_string());
                }
                break;
            }

            if let Some(soh_pos) = remaining.iter().position(|&b| b == 0x01) {
                remaining = &remaining[soh_pos + 1..];
            } else {
                break;
            }
        }

        None
    }
}

// Helper function
pub fn validate_packet_length(data: &[u8], min_len: usize, max_len: usize) -> Result<(), PacketError> {
    if data.len() < min_len {
        return Err(PacketError::TooShort {
            expected: min_len,
            actual: data.len(),
        });
    }

    if data.len() > max_len {
        return Err(PacketError::TooLong {
            expected: max_len,
            actual: data.len(),
        });
    }

    Ok(())
}

