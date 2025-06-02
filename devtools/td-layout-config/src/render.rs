// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use serde_json::Value;
use std::collections::HashMap;
use tera::{Context, Result, Tera};

use super::layout::{LayoutConfig, ENTRY_TYPE_FILTER};

/// Render image layout file.
pub fn render_image(image_layout: &LayoutConfig, fw_top: usize) -> Result<String> {
    let mut tera = Tera::default();
    tera.register_filter("format_hex", format_hex);
    tera.register_filter("format_name", format_name);
    tera.register_filter("format_layout_border", format_layout_border);
    tera.add_raw_template("image.rs", include_str!("template/image.jinja"))
        .expect("Template parse failed!");
    let mut context = Context::new();
    context.insert("image_regions", image_layout.get_regions());
    context.insert("image_size", &image_layout.get_top());
    // Image size - metadata pointer offset(0x20) - OVMF GUID table size(0x28) - SEC Core information size(0xC).
    context.insert("sec_info_offset", &(image_layout.get_top() - 0x54));
    context.insert("memory_offset", &(fw_top - &image_layout.get_top()));
    context.insert("entry_type_filter", ENTRY_TYPE_FILTER);
    tera.render("image.rs", &context)
}

/// Render memory layout file.
pub fn render_memory(memory_layout: &LayoutConfig) -> Result<String> {
    let mut tera = Tera::default();
    tera.register_filter("format_hex", format_hex);
    tera.register_filter("format_name", format_name);
    tera.register_filter("format_layout_border", format_layout_border);
    tera.add_raw_template("memory.rs", include_str!("template/memory.jinja"))
        .expect("Template parse failed!");
    let mut context = Context::new();
    context.insert("memory_regions", memory_layout.get_regions());
    context.insert("tolm", &memory_layout.get_top());
    context.insert("total_usage", &memory_layout.get_total_usage());
    context.insert("memory_regions_base", &memory_layout.get_base());
    context.insert("entry_type_filter", ENTRY_TYPE_FILTER);
    tera.render("memory.rs", &context)
}

/// Formats integers to hex format
///
pub fn format_hex(value: &Value, _args: &HashMap<String, Value>) -> Result<Value> {
    let value = format!("0x{:X}", value.as_u64().unwrap());
    Ok(Value::String(value))
}

/// For render Layout
const MAX_LAYOUT_REGION_NAME_LEN: usize = 40;

/// Formats name add space
///
pub fn format_name(value: &Value, _args: &HashMap<String, Value>) -> Result<Value> {
    let value = format!(
        "{:^1$}",
        value.as_str().unwrap(),
        MAX_LAYOUT_REGION_NAME_LEN
    );
    Ok(Value::String(value))
}

/// Add +------------------------+ border notation.
pub fn format_layout_border(_: &Value, _args: &HashMap<String, Value>) -> Result<Value> {
    let border = format!("+{:-^1$}+", "", MAX_LAYOUT_REGION_NAME_LEN);
    Ok(Value::String(border))
}
