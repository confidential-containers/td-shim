use crate::layout_builder::region::MemoryRegions;
use json5;
use serde::Deserialize;

#[derive(Deserialize, Debug, PartialEq)]
struct Layout {
    pub name: String,
    pub length: usize,
}

pub fn parse_memory<P: ToString>(mut memory_regions: MemoryRegions, data: P) -> MemoryRegions {
    let layouts: Vec<Layout> = json5::from_str(
        &std::fs::read_to_string(data.to_string())
            .expect("Content is configuration file is invalid"),
    )
    .expect("Content is configuration file is invalid");

    for layout in layouts.iter() {
        memory_regions = memory_regions.create_region(&layout.name, layout.length);
    }
    memory_regions
}
