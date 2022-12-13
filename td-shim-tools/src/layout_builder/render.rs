// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::layout_builder::region::MemoryRegions;
use serde_json::Value;
use std::collections::HashMap;
use tera::{Context, Result, Tera};

/// Render output layout file.
pub fn render(memory_regions: &MemoryRegions) -> Result<String> {
    let mut tera = Tera::default();
    tera.register_filter("format_hex", format_hex);
    tera.register_filter("format_name", format_name);
    tera.register_filter("format_mem_layout_border", format_mem_layout_border);
    tera.add_raw_template("layout.rs", include_str!("layout.rs.jinja"))
        .expect("Template parse failed!");
    let mut context = Context::new();
    context.insert("memory_regions", memory_regions.get_regions());
    context.insert("total_memory_length", &memory_regions.get_total_length());
    context.insert("memory_regions_base", &memory_regions.get_base());
    tera.render("layout.rs", &context)
}

/// Formats integers to hex format
///
pub fn format_hex(value: &Value, _args: &HashMap<String, Value>) -> Result<Value> {
    let value = format!("0x{:X}", value.as_u64().unwrap());
    Ok(Value::String(value))
}

/// Formats name add space
///
pub fn format_name(value: &Value, _args: &HashMap<String, Value>) -> Result<Value> {
    let value = format_name_string(value.as_str().unwrap());
    Ok(Value::String(value))
}

/// For render Mem Layout
const MAX_MEMORY_REGION_NAME_LEN: usize = 40;

/// Add +------------------------+ border notation.
pub fn format_mem_layout_border(_: &Value, _args: &HashMap<String, Value>) -> Result<Value> {
    let mut v = String::new();
    v.push('+');
    for _ in 0..MAX_MEMORY_REGION_NAME_LEN {
        v.push('-');
    }
    v.push('+');
    Ok(Value::String(v))
}

fn format_name_string(s: &str) -> String {
    let len = s.chars().count();
    let prefix_len = (MAX_MEMORY_REGION_NAME_LEN - len) / 2;
    let suffix_len = MAX_MEMORY_REGION_NAME_LEN - len - prefix_len;
    let mut v = String::new();
    for _ in 0..prefix_len {
        v.push(' ');
    }
    v.push_str(s);
    for _ in 0..suffix_len {
        v.push(' ');
    }
    v
}
