use core::{convert::TryInto, mem::size_of, ptr::slice_from_raw_parts, str::FromStr};

use scroll::{Pread, Pwrite};

// use alloc::borrow::ToOwned;

const GUID_STRING_LEN: usize = 36;
const GUID_SPLITTER: u8 = b'-';

// A GUID is a 128-bit integer (16 bytes) that can be
// used as a unique identifier.
#[repr(C)]
#[derive(Debug, Default, PartialEq, Eq, Pwrite, Pread)]
pub struct Guid {
    f0: u32,
    f1: u16,
    f2: u16,
    f3: [u8; 8],
}

#[derive(Debug)]
pub enum GuidParseError {
    InvalidInput,
}

impl Guid {
    // Create a GUID instance from several fields
    pub const fn from_fields(f0: u32, f1: u16, f2: u16, f3: [u8; 8]) -> Guid {
        Self { f0, f1, f2, f3 }
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        // Safe since the size of Guid is 16
        unsafe {
            (&*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()))
                .try_into()
                .unwrap()
        }
    }

    pub fn from_bytes(buffer: &[u8; 16]) -> Guid {
        let f0 = u32::from_le_bytes(buffer[0..4].try_into().unwrap());
        let f1 = u16::from_le_bytes(buffer[4..6].try_into().unwrap());
        let f2 = u16::from_le_bytes(buffer[6..8].try_into().unwrap());
        let mut f3: [u8; 8] = [0; 8];
        f3.copy_from_slice(&buffer[8..]);

        Self { f0, f1, f2, f3 }
    }
}

impl FromStr for Guid {
    type Err = GuidParseError;

    // Create a GUID instance from a string slice
    // Input should follow format strictly: "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
    // For example: "F9168C5E-CEB2-4faa-B6BF-329BF39FA1E4"
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let b = s.as_bytes();
        if b.len() != GUID_STRING_LEN
            || b[8] != GUID_SPLITTER
            || b[13] != GUID_SPLITTER
            || b[18] != GUID_SPLITTER
            || b[23] != GUID_SPLITTER
        {
            return Err(GuidParseError::InvalidInput);
        }

        let parse_hex = |s: &str| -> Option<u64> {
            for c in s.as_bytes() {
                if !c.is_ascii_hexdigit() {
                    return None;
                }
            }
            u64::from_str_radix(s, 16).ok()
        };

        // Parse the string into fields
        let f0 = parse_hex(&s[0..8]).ok_or(GuidParseError::InvalidInput)? as u32;
        let f1 = parse_hex(&s[9..13]).ok_or(GuidParseError::InvalidInput)? as u16;
        let f2 = parse_hex(&s[14..18]).ok_or(GuidParseError::InvalidInput)? as u16;
        let mut f3 = parse_hex(&s[19..23]).ok_or(GuidParseError::InvalidInput)? << 48;
        f3 |= parse_hex(&s[24..36]).ok_or(GuidParseError::InvalidInput)?;

        // f3 is decoded from string so use big endian to encode into bytes
        Ok(Self {
            f0,
            f1,
            f2,
            f3: u64::to_be_bytes(f3),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_guid() {
        // F9168C5E-CEB2-4faa-B6BF-329BF39FA1E4
        let guid_bytes = [
            0x5E, 0x8C, 0x16, 0xF9, 0xB2, 0xCE, 0xaa, 0x4f, 0xB6, 0xBF, 0x32, 0x9B, 0xF3, 0x9F,
            0xA1, 0xE4,
        ];
        let guid_field = Guid::from_fields(
            0xF9168C5E,
            0xCEB2,
            0x4faa,
            [0xB6, 0xBF, 0x32, 0x9B, 0xF3, 0x9F, 0xA1, 0xE4],
        );

        assert_eq!(&guid_bytes, guid_field.as_bytes());

        let guid_str = Guid::from_str("F9168C5E-CEB2-4faa-B6BF-329BF39FA1E4").unwrap();
        assert_eq!(&guid_bytes, guid_str.as_bytes());

        let guid_str = Guid::from_str("F9168C5E");
        assert!(guid_str.is_err());

        let guid_str = Guid::from_str("F9168C5E-CEB2-4faa-B6BF-329");
        assert!(guid_str.is_err());

        let guid_str = Guid::from_str("F9168C5E-CEB2-4faaB6-BF-329BF39FA1E4");
        assert!(guid_str.is_err());

        let guid_str = Guid::from_str("+9168C5E-CEB2-4faa-B6BF-329BF39FA1E4");
        assert!(guid_str.is_err());

        let guid_str = Guid::from_str("F9168C5ECCEB2C4faaCB6BFC329BF39FA1E4");
        assert!(guid_str.is_err());
    }
}
