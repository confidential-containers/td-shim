// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use serde::Deserialize;

use super::{layout::LayoutConfig, render};

const ROM_BASE: usize = 0xFF00_0000;
const ROM_SIZE: usize = 0x100_0000;

#[derive(Deserialize, Debug, PartialEq)]
struct ImageConfig {
    #[serde(rename = "LargePayload")]
    large_payload: Option<String>,
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

    let large_payload_size = image_config
        .large_payload
        .map(|large_payload| parse_int::parse::<u32>(&large_payload).unwrap() as usize);
    let config_size = parse_int::parse::<u32>(&image_config.config).unwrap() as usize;
    let mailbox_size = parse_int::parse::<u32>(&image_config.mailbox).unwrap() as usize;
    let temp_stack_size = parse_int::parse::<u32>(&image_config.temp_stack).unwrap() as usize;
    let temp_heap_size = parse_int::parse::<u32>(&image_config.temp_heap).unwrap() as usize;
    let reset_vector_size = parse_int::parse::<u32>(&image_config.reset_vector).unwrap() as usize;
    let bootloader_size = parse_int::parse::<u32>(&image_config.bootloader).unwrap() as usize;
    let metadata_size = parse_int::parse::<u32>(&image_config.metadata).unwrap() as usize;
    let td_info_size = image_config
        .td_info
        .map(|td_info| parse_int::parse::<u32>(&td_info).unwrap() as usize);
    let payload_size = image_config
        .builtin_payload
        .map(|payload| parse_int::parse::<u32>(&payload).unwrap() as usize);

    let image_size = large_payload_size.unwrap_or(0)
        + config_size
        + mailbox_size
        + temp_stack_size
        + temp_heap_size
        + reset_vector_size
        + bootloader_size
        + metadata_size
        + td_info_size.unwrap_or(0)
        + payload_size.unwrap_or(0);

    let mut image_layout = LayoutConfig::new(0, image_size);
    if let Some(size) = large_payload_size {
        image_layout.reserve_low("LargePayload", size, "Reserved")
    }
    image_layout.reserve_low("Config", config_size, "Reserved");
    image_layout.reserve_low("Mailbox", mailbox_size, "Reserved");
    image_layout.reserve_low("TempStack", temp_stack_size, "Reserved");
    image_layout.reserve_low("TempHeap", temp_heap_size, "Reserved");
    image_layout.reserve_high("ResetVector", reset_vector_size, "Reserved");
    image_layout.reserve_high("Ipl", bootloader_size, "Reserved");
    image_layout.reserve_high("Metadata", metadata_size, "Reserved");
    if let Some(size) = td_info_size {
        image_layout.reserve_high("TdInfo", size, "Reserved")
    }
    if let Some(size) = payload_size {
        image_layout.reserve_high("Payload", size, "Reserved")
    }

    let mut rom_layout = LayoutConfig::new(ROM_BASE, ROM_BASE + ROM_SIZE);
    rom_layout.reserve_low("Config", config_size, "Reserved");
    rom_layout.reserve_low("Mailbox", mailbox_size, "Reserved");
    rom_layout.reserve_low("TempStack", temp_stack_size, "Reserved");
    rom_layout.reserve_low("TempHeap", temp_heap_size, "Reserved");
    rom_layout.reserve_high("ResetVector", reset_vector_size, "Reserved");
    rom_layout.reserve_high("Ipl", bootloader_size, "Reserved");
    rom_layout.reserve_high("Metadata", metadata_size, "Reserved");
    if let Some(size) = td_info_size {
        rom_layout.reserve_high("TdInfo", size, "Reserved")
    }
    if let Some(size) = payload_size {
        rom_layout.reserve_high("Payload", size, "Reserved")
    }

    render::render_image(&image_layout, &rom_layout).expect("Render image layout failed!")
}
