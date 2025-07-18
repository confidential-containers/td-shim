// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use serde::Deserialize;

use super::{layout::LayoutConfig, render};

#[derive(Deserialize, Debug, PartialEq)]
struct ImageConfig {
    #[serde(rename = "Config")]
    config: Option<String>,
    #[serde(rename = "Mailbox")]
    mailbox: Option<String>,
    #[serde(rename = "TempStack")]
    temp_stack: String,
    #[serde(rename = "TempHeap")]
    temp_heap: String,
    #[serde(rename = "Payload")]
    builtin_payload: Option<String>,
    #[serde(rename = "TdInfo")]
    td_info: Option<String>,
    #[serde(rename = "TdParams")]
    td_params: Option<String>,
    #[serde(rename = "Metadata")]
    metadata: String,
    #[serde(rename = "Ipl")]
    bootloader: String,
    #[serde(rename = "ResetVector")]
    reset_vector: String,
    #[serde(rename = "ImageSize")]
    image_size: Option<String>,
}

pub fn parse_image(data: String, fw_top: usize) -> String {
    let image_config = serde_json::from_str::<ImageConfig>(&data)
        .expect("Content is configuration file is invalid");

    let mut image_size = 0x100_0000 as usize;
    if image_config.image_size.is_some() {
        image_size = parse_int::parse::<u32>(&image_config.image_size.unwrap()).unwrap() as usize;
    }

    let mut image_layout = LayoutConfig::new(0, image_size);

    if let Some(config_config) = image_config.config {
        image_layout.reserve_low(
            "Config",
            parse_int::parse::<u32>(&config_config).unwrap() as usize,
            "Reserved",
        );
    } else {
        image_layout.reserve_low("Config", 0usize, "Reserved");
    }
    if let Some(mailbox_config) = image_config.mailbox {
        image_layout.reserve_low(
            "Mailbox",
            parse_int::parse::<u32>(&mailbox_config).unwrap() as usize,
            "Reserved",
        );
    } else {
        image_layout.reserve_low("Mailbox", 0usize, "Reserved");
    }

    image_layout.reserve_low(
        "TempStack",
        parse_int::parse::<u32>(&image_config.temp_stack).unwrap() as usize,
        "Reserved",
    );
    image_layout.reserve_low(
        "TempHeap",
        parse_int::parse::<u32>(&image_config.temp_heap).unwrap() as usize,
        "Reserved",
    );

    image_layout.reserve_high(
        "ResetVector",
        parse_int::parse::<u32>(&image_config.reset_vector).unwrap() as usize,
        "Reserved",
    );
    image_layout.reserve_high(
        "Ipl",
        parse_int::parse::<u32>(&image_config.bootloader).unwrap() as usize,
        "Reserved",
    );

    image_layout.reserve_high(
        "Metadata",
        parse_int::parse::<u32>(&image_config.metadata).unwrap() as usize,
        "Reserved",
    );

    if let Some(td_info_config) = image_config.td_info {
        image_layout.reserve_high(
            "TdInfo",
            parse_int::parse::<u32>(&td_info_config).unwrap() as usize,
            "Reserved",
        )
    }

    if let Some(td_params_config) = image_config.td_params {
        image_layout.reserve_high(
            "TdParams",
            parse_int::parse::<u32>(&td_params_config).unwrap() as usize,
            "Reserved",
        )
    }

    if let Some(payload_config) = image_config.builtin_payload {
        image_layout.reserve_high(
            "Payload",
            parse_int::parse::<u32>(&payload_config).unwrap() as usize,
            "Reserved",
        )
    }

    render::render_image(&image_layout, fw_top).expect("Render image layout failed!")
}
