use serde::Deserialize;

use super::{layout::LayoutConfig, render};

#[derive(Deserialize, Debug, PartialEq)]
struct ImageConfig {
    #[serde(rename = "CONFIG")]
    config: String,
    #[serde(rename = "MAILBOX")]
    mailbox: String,
    #[serde(rename = "TEMP_STACK")]
    temp_stack: String,
    #[serde(rename = "TEMP_HEAP")]
    temp_heap: String,
    #[serde(rename = "PAYLOAD")]
    builtin_payload: Option<String>,
    #[serde(rename = "METADATA")]
    metadata: String,
    #[serde(rename = "IPL")]
    bootloader: String,
    #[serde(rename = "RESET_VECTOR")]
    reset_vector: String,
}

pub fn parse_image(data: String) -> String {
    let image_config = serde_json::from_str::<ImageConfig>(&data)
        .expect("Content is configuration file is invalid");

    let mut image_layout = LayoutConfig::new(0, 0x100_0000);
    image_layout.reserve_low(
        "CONFIG",
        parse_int::parse::<u32>(&image_config.config).unwrap() as usize,
        "Reserved",
    );
    image_layout.reserve_low(
        "MAILBOX",
        parse_int::parse::<u32>(&image_config.mailbox).unwrap() as usize,
        "Reserved",
    );
    image_layout.reserve_low(
        "TEMP_STACK",
        parse_int::parse::<u32>(&image_config.temp_stack).unwrap() as usize,
        "Reserved",
    );
    image_layout.reserve_low(
        "TEMP_HEAP",
        parse_int::parse::<u32>(&image_config.temp_heap).unwrap() as usize,
        "Reserved",
    );

    image_layout.reserve_high(
        "RESET_VECTOR",
        parse_int::parse::<u32>(&image_config.reset_vector).unwrap() as usize,
        "Reserved",
    );
    image_layout.reserve_high(
        "IPL",
        parse_int::parse::<u32>(&image_config.bootloader).unwrap() as usize,
        "Reserved",
    );

    image_layout.reserve_high(
        "METADATA",
        parse_int::parse::<u32>(&image_config.metadata).unwrap() as usize,
        "Reserved",
    );

    if let Some(payload_config) = image_config.builtin_payload {
        image_layout.reserve_high(
            "PAYLOAD",
            parse_int::parse::<u32>(&payload_config).unwrap() as usize,
            "Reserved",
        )
    }

    render::render_image(&image_layout).expect("Render image layout failed!")
}
