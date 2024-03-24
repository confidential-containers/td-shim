use serde::Deserialize;

use super::{layout::LayoutConfig, render};

const FIRMWARE_ROM_BASE: usize = 0xFF00_0000;
const FIRMWARE_ROM_SIZE: usize = 0x100_0000;

#[derive(Deserialize, Debug, PartialEq)]
struct ImageConfig {
    #[serde(rename = "Config")]
    config: String,
    #[serde(rename = "Mailbox")]
    mailbox: String,
    #[serde(rename = "TempStack")]
    temp_stack: String,
    #[serde(rename = "TempHeap")]
    temp_heap: String,
    #[serde(rename = "Payload")]
    builtin_payload: Option<String>,
    #[serde(rename = "TdInfo")]
    td_info: Option<String>,
    #[serde(rename = "Metadata")]
    metadata: String,
    #[serde(rename = "Ipl")]
    bootloader: String,
    #[serde(rename = "ResetVector")]
    reset_vector: String,
}

pub fn parse_image(data: String) -> String {
    let image_config = serde_json::from_str::<ImageConfig>(&data)
        .expect("Content is configuration file is invalid");

    let config_size = parse_int::parse::<u32>(&image_config.config).unwrap() as usize;
    let mailbox_size = parse_int::parse::<u32>(&image_config.mailbox).unwrap() as usize;
    let temp_stack_size = parse_int::parse::<u32>(&image_config.temp_stack).unwrap() as usize;
    let temp_heap_size = parse_int::parse::<u32>(&image_config.temp_heap).unwrap() as usize;
    let reset_vector_size = parse_int::parse::<u32>(&image_config.reset_vector).unwrap() as usize;
    let ipl_size = parse_int::parse::<u32>(&image_config.bootloader).unwrap() as usize;
    let metadata_size = parse_int::parse::<u32>(&image_config.metadata).unwrap() as usize;
    let payload_size = parse_int::parse::<u32>(
        &image_config
            .builtin_payload
            .unwrap_or_else(|| "0".to_string()),
    )
    .unwrap() as usize;
    let td_info_size =
        parse_int::parse::<u32>(&image_config.td_info.unwrap_or_else(|| "0".to_string())).unwrap()
            as usize;

    // Build firmware image layout
    let image_size = config_size
        + reset_vector_size
        + mailbox_size
        + temp_heap_size
        + temp_stack_size
        + ipl_size
        + metadata_size
        + payload_size
        + td_info_size;
    let mut image_layout = LayoutConfig::new(0, image_size);
    image_layout.reserve_low("Config", config_size, "Image");
    image_layout.reserve_low("Mailbox", mailbox_size, "Rom");
    image_layout.reserve_low("TempStack", temp_stack_size, "Rom");
    image_layout.reserve_low("TempHeap", temp_heap_size, "Rom");
    image_layout.reserve_high("ResetVector", reset_vector_size, "Image");
    image_layout.reserve_high("Ipl", ipl_size, "Image");
    image_layout.reserve_high("Metadata", metadata_size, "Image");
    if td_info_size != 0 {
        image_layout.reserve_high("TdInfo", td_info_size, "Image")
    }
    if payload_size != 0 {
        image_layout.reserve_high("Payload", payload_size, "Image")
    }

    // Build ROM layout at memory space: 0xFF00_0000 - 0xFFFF_FFFF
    // Payload image is not loaded into ROM space.
    let mut rom_layout =
        LayoutConfig::new(FIRMWARE_ROM_BASE, FIRMWARE_ROM_BASE + FIRMWARE_ROM_SIZE);
    rom_layout.reserve_low("Config", config_size, "Rom");
    rom_layout.reserve_low("Mailbox", mailbox_size, "Rom");
    rom_layout.reserve_low("TempStack", temp_stack_size, "Rom");
    rom_layout.reserve_low("TempHeap", temp_heap_size, "Rom");
    rom_layout.reserve_high("ResetVector", reset_vector_size, "Rom");
    rom_layout.reserve_high("Ipl", ipl_size, "Rom");
    rom_layout.reserve_high("Metadata", metadata_size, "Rom");
    if td_info_size != 0 {
        rom_layout.reserve_high("TdInfo", td_info_size, "Rom")
    }

    render::render_image(&image_layout, &rom_layout).expect("Render image layout failed!")
}
