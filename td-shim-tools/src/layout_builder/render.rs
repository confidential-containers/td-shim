// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use serde_json::Value;
use std::collections::HashMap;
use tera::{Context, Result, Tera};

use super::region::LayoutConfig;

/// Render memory layout file.
pub fn render_memory(memory_layout: &LayoutConfig) -> Result<String> {
    let mut tera = Tera::default();
    tera.register_filter("format_hex", format_hex);
    tera.register_filter("format_name", format_name);
    tera.register_filter("format_mem_layout_border", format_mem_layout_border);
    tera.add_raw_template("memory.rs", include_str!("layout.rs.jinja"))
        .expect("Template parse failed!");
    let mut context = Context::new();
    context.insert("memory_regions", memory_layout.get_regions());
    context.insert("total_memory_length", &memory_layout.get_total_length());
    context.insert("total_usage", &memory_layout.get_total_usage());
    context.insert("memory_regions_base", &memory_layout.get_base());
    tera.render("memory.rs", &context)
}

/// Formats integers to hex format
///
pub fn format_hex(value: &Value, _args: &HashMap<String, Value>) -> Result<Value> {
    let value = format!("0x{:X}", value.as_u64().unwrap());
    Ok(Value::String(value))
}

/// For render Mem Layout
const MAX_MEMORY_REGION_NAME_LEN: usize = 40;

/// Formats name add space
///
pub fn format_name(value: &Value, _args: &HashMap<String, Value>) -> Result<Value> {
    let value = format!(
        "{:^1$}",
        value.as_str().unwrap(),
        MAX_MEMORY_REGION_NAME_LEN
    );
    Ok(Value::String(value))
}

/// Add +------------------------+ border notation.
pub fn format_mem_layout_border(_: &Value, _args: &HashMap<String, Value>) -> Result<Value> {
    let border = format!("+{:-^1$}+", "", MAX_MEMORY_REGION_NAME_LEN);
    Ok(Value::String(border))
}
