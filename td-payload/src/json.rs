// Copyright © 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloc::string::String;
use r_efi::efi::Guid;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct SerdeJsonTest {
    #[serde(with = "guid")]
    test_guid: Guid,
    #[serde(with = "range")]
    test_range_inclu: range::Range,
    #[serde(with = "range")]
    test_range_exclu: range::Range,
    #[serde(with = "range")]
    test_range_hex: range::Range,
    #[serde(with = "hex")]
    test_u32: u32,
    test_bool: bool,
    test_u16: u16,
    test_string: String,
    test_array: [u32; 5],
}

pub fn json_test() {
    let zero = SerdeJsonTest {
        //{B0BAE802-534F-4974-942D-2EDE15BC1AE8}
        test_guid: Guid::from_fields(
            0xB0BAE802,
            0x534F,
            0x4974,
            0x94,
            0x2D,
            &[0x2E, 0xDE, 0x15, 0xBC, 0x1A, 0xE8],
        ),
        test_range_inclu: range::new(false, 2, true, i64::MAX),
        test_range_exclu: range::new(true, -2, true, 5),
        test_range_hex: range::new(true, 16, false, 32),
        test_u32: 0x00001000,
        test_bool: true,
        test_u16: 256,
        test_string: String::from("A test"),
        test_array: [1, 2, 3, 4, 5],
    };

    let config = r#"
        {
            "test_guid":"B0BAE802-534F-4974-942D-2EDE15BC1AE8",
            "test_range_inclu":"[2..inf)",
            "test_range_exclu":"(-2..5)",
            "test_range_hex":"(0x10..0x20]",
            "test_u32": "0x00001000",
            "test_bool": true,
            "test_u16": 256,
            "test_string": "A test",
            "test_array": [1, 2, 3, 4, 5],
            "test_time":"1996-12-19T16:39:57-08:00",
            "test_time_stamp":1431684000
        }
    "#;
    let bytes_config = config.as_bytes();

    let one: SerdeJsonTest =
        serde_json::from_slice(bytes_config).expect("It is not a successful JSON test.");
    assert_eq!(zero, one);
}

mod guid {
    use r_efi::efi::Guid;
    use serde::{de::Error, Deserialize, Deserializer, Serializer};
    pub fn serialize<S>(guid: &Guid, serialize: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let (time_low, time_mid, time_hi_and_version, clk_seq_hi_res, clk_seq_low, node) =
            guid.as_fields();
        let str = format!(
            "{:08X?}-{:04X?}-{:04X?}-{:02X?}{:02X?}-{:02X?}{:02X?}{:02X?}{:02X?}{:02X?}{:02X?}",
            time_low,
            time_mid,
            time_hi_and_version,
            clk_seq_hi_res,
            clk_seq_low,
            node[0],
            node[1],
            node[2],
            node[3],
            node[4],
            node[5]
        );
        serialize.serialize_str(&str)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Guid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deserializer)?;
        Ok(Guid::from_fields(
            u32::from_str_radix(&s[0..8], 16).map_err(D::Error::custom)?,
            u16::from_str_radix(&s[9..13], 16).map_err(D::Error::custom)?,
            u16::from_str_radix(&s[14..18], 16).map_err(D::Error::custom)?,
            u8::from_str_radix(&s[19..21], 16).map_err(D::Error::custom)?,
            u8::from_str_radix(&s[21..23], 16).map_err(D::Error::custom)?,
            &[
                u8::from_str_radix(&s[24..26], 16).map_err(D::Error::custom)?,
                u8::from_str_radix(&s[26..28], 16).map_err(D::Error::custom)?,
                u8::from_str_radix(&s[28..30], 16).map_err(D::Error::custom)?,
                u8::from_str_radix(&s[30..32], 16).map_err(D::Error::custom)?,
                u8::from_str_radix(&s[32..34], 16).map_err(D::Error::custom)?,
                u8::from_str_radix(&s[34..36], 16).map_err(D::Error::custom)?,
            ],
        ))
    }
}

mod range {
    use alloc::string::ToString;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn new(exclusive_min: bool, min: i64, exclusive_max: bool, max: i64) -> Range {
        Range {
            exclusive_min,
            min,
            exclusive_max,
            max,
        }
    }

    #[derive(Debug, PartialEq)]
    pub struct Range {
        exclusive_min: bool,
        min: i64,
        exclusive_max: bool,
        max: i64,
    }

    pub fn serialize<S>(range: &Range, serialize: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let str = format!(
            "{}{}..{}{}",
            if range.exclusive_min { '(' } else { '[' },
            if range.min == i64::MIN {
                "-inf".to_string()
            } else {
                range.min.to_string()
            },
            if range.max == i64::MAX {
                "inf".to_string()
            } else {
                range.max.to_string()
            },
            if range.exclusive_max { ')' } else { ']' },
        );
        serialize.serialize_str(&str)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Range, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deserializer)?;
        let len = s.len();
        let exclu_max = b')' == s.as_bytes()[len - 1];
        let exclu_min = b'(' == s.as_bytes()[0];
        let dot_dot = s.find("..").unwrap();
        fn str_to_int64(s: &str) -> i64 {
            match s {
                "-inf" => i64::MIN,
                "inf" => i64::MAX,
                _ => {
                    if s.len() > 2 && (&s[..2] == "0x" || &s[..2] == "0X") {
                        i64::from_str_radix(&s[2..], 16).unwrap()
                    } else {
                        s.parse::<i64>().unwrap()
                    }
                }
            }
        }
        let min = str_to_int64(&s[1..dot_dot]);
        let max = str_to_int64(&s[dot_dot + 2..len - 1]);
        Ok(Range {
            exclusive_max: exclu_max,
            exclusive_min: exclu_min,
            min: min,
            max: max,
        })
    }
}

mod hex {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};
    pub fn serialize<S>(num: &u32, serialize: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let str = format!("0x{:x}", num);
        serialize.serialize_str(&str)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u32, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deserializer)?;
        if s.len() > 2 && (&s[..2] == "0x" || &s[..2] == "0X") {
            u32::from_str_radix(&s[2..], 16).map_err(D::Error::custom)
        } else {
            s.parse::<u32>().map_err(D::Error::custom)
        }
    }
}
