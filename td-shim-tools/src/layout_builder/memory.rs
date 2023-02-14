use serde::Deserialize;

use super::{layout::LayoutConfig, render};

#[derive(Deserialize, Debug, PartialEq)]
struct Region {
    pub name: String,
    pub size: String,
    pub r#type: String,
}

#[derive(Deserialize, Debug)]
struct MemoryConfig {
    memory_regions: Vec<Region>,
}

pub fn parse_memory(data: String) -> String {
    let memory_config = serde_json::from_str::<MemoryConfig>(&data)
        .expect("Content is configuration file is invalid");

    let mut memory_layout = LayoutConfig::new(0x0, 0x8000_0000);

    for region in memory_config.memory_regions {
        let size = parse_int::parse::<usize>(&region.size).unwrap();
        if region.r#type.as_str() == "Memory" {
            memory_layout.reserve_low(&region.name, size, &region.r#type);
        } else {
            memory_layout.reserve_high(&region.name, size, &region.r#type);
        }
    }

    render::render_memory(&memory_layout).expect("Render memory layout failed!")
}
