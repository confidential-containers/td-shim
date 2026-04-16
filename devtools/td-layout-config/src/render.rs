// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use chrono::Local;
use humansize::format_size;
use serde_json::Value;
use std::collections::HashMap;
use tera::{Context, Result, Tera};

use super::layout::{LayoutConfig, ENTRY_TYPE_FILTER};

/// Register builtin functions/filters that are normally behind tera's "builtins"
/// feature, which we disable to avoid pulling in the vulnerable rand 0.8.5 crate.
fn register_builtins(tera: &mut Tera) {
    tera.register_function("now", now);
    tera.register_filter("date", date);
    tera.register_filter("filesizeformat", filesizeformat);
}

fn now(args: &HashMap<String, tera::Value>) -> Result<tera::Value> {
    let utc = args.get("utc").and_then(|v| v.as_bool()).unwrap_or(false);
    let timestamp = args
        .get("timestamp")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if utc {
        let dt = chrono::Utc::now();
        if timestamp {
            return Ok(serde_json::to_value(dt.timestamp()).unwrap());
        }
        Ok(serde_json::to_value(dt.to_rfc3339()).unwrap())
    } else {
        let dt = Local::now();
        if timestamp {
            return Ok(serde_json::to_value(dt.timestamp()).unwrap());
        }
        Ok(serde_json::to_value(dt.to_rfc3339()).unwrap())
    }
}

fn date(value: &Value, args: &HashMap<String, Value>) -> Result<Value> {
    let format = match args.get("format") {
        Some(val) => val
            .as_str()
            .ok_or_else(|| tera::Error::msg("Filter `date` received a non-string `format`"))?
            .to_string(),
        None => "%Y-%m-%d".to_string(),
    };
    match value {
        Value::String(s) => {
            use chrono::{DateTime, FixedOffset, NaiveDateTime};
            if s.contains('T') {
                let dt: DateTime<FixedOffset> = s
                    .parse()
                    .map_err(|_| tera::Error::msg(format!("Failed to parse datetime `{s}`")))?;
                Ok(Value::String(dt.format(&format).to_string()))
            } else {
                let dt = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
                    .map_err(|_| tera::Error::msg(format!("Failed to parse datetime `{s}`")))?;
                Ok(Value::String(dt.format(&format).to_string()))
            }
        }
        Value::Number(n) => {
            let i = n.as_i64().ok_or_else(|| {
                tera::Error::msg(format!("Filter `date` was invoked on a float: {n}"))
            })?;
            let dt = chrono::DateTime::from_timestamp(i, 0)
                .ok_or_else(|| tera::Error::msg("Timestamp out of range"))?
                .naive_utc();
            Ok(Value::String(dt.format(&format).to_string()))
        }
        _ => Err(tera::Error::msg(format!(
            "Filter `date` received an invalid value: `{value}`"
        ))),
    }
}

fn filesizeformat(value: &Value, args: &HashMap<String, Value>) -> Result<Value> {
    let num: usize = serde_json::from_value(value.clone())
        .map_err(|_| tera::Error::msg("Filter `filesizeformat` received a non-number value"))?;
    let binary = args
        .get("binary")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let format = if binary {
        humansize::BINARY
    } else {
        humansize::WINDOWS
    };
    Ok(serde_json::to_value(format_size(num, format)).unwrap())
}

/// Render image layout file.
pub fn render_image(image_layout: &LayoutConfig, fw_top: usize) -> Result<String> {
    let mut tera = Tera::default();
    register_builtins(&mut tera);
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
    register_builtins(&mut tera);
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
