use crate::layout_builder::region::MemoryRegions;
use json5;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize, Debug, PartialEq)]
struct Layout {
    pub name: String,
    pub length: usize,
}

pub fn parse_memory<P: ToString>(mut memory_regions: MemoryRegions, data: P) -> MemoryRegions {
    let layout_config: Value = json5::from_str(
        &std::fs::read_to_string(data.to_string())
            .expect("Content is configuration file is invalid"),
    )
    .expect("Content is configuration file is invalid");

    let td_hob_size = layout_config["runtime_layout"]["td_hob_size"]
        .as_u64()
        .unwrap() as usize;
    let kernel_param_size = layout_config["runtime_layout"]["kernel_param_size"]
        .as_u64()
        .unwrap() as usize;
    let kernel_size = layout_config["runtime_layout"]["kernel_size"]
        .as_u64()
        .unwrap() as usize;
    let unaccepted_memory_bitmap_size = layout_config["runtime_layout"]
        ["unaccepted_memory_bitmap_size"]
        .as_u64()
        .unwrap() as usize;
    let acpi_size = layout_config["runtime_layout"]["acpi_size"]
        .as_u64()
        .unwrap() as usize;
    let stack_size = layout_config["runtime_layout"]["stack_size"]
        .as_u64()
        .unwrap() as usize;
    let payload_size = layout_config["runtime_layout"]["payload_size"]
        .as_u64()
        .unwrap() as usize;
    let page_table_size = layout_config["runtime_layout"]["page_table_size"]
        .as_u64()
        .unwrap() as usize;
    let mailbox_size = layout_config["runtime_layout"]["mailbox_size"]
        .as_u64()
        .unwrap() as usize;
    let event_log_size = layout_config["runtime_layout"]["event_log_size"]
        .as_u64()
        .unwrap() as usize;

    let reserved2_size = 0x8000_0000
        - 0x10_0000
        - 0x70_0000
        - td_hob_size
        - kernel_param_size
        - kernel_size
        - unaccepted_memory_bitmap_size
        - acpi_size
        - stack_size
        - payload_size
        - page_table_size
        - mailbox_size
        - event_log_size;

    memory_regions = memory_regions.create_region("LEGACY", 0x10_0000);
    memory_regions = memory_regions.create_region("RESERVED1", 0x70_0000);
    memory_regions = memory_regions.create_region("TD_HOB", td_hob_size);
    memory_regions = memory_regions.create_region("KERNEL_PARAM", kernel_param_size);
    memory_regions = memory_regions.create_region("KERNEL", kernel_size);
    memory_regions = memory_regions.create_region("RESERVED2", reserved2_size);
    memory_regions = memory_regions.create_region(
        "TD_PAYLOAD_UNACCEPTED_MEMORY_BITMAP",
        unaccepted_memory_bitmap_size,
    );
    memory_regions = memory_regions.create_region("TD_PAYLOAD_ACPI", acpi_size);
    memory_regions = memory_regions.create_region("TD_PAYLOAD_STACK", stack_size);
    memory_regions = memory_regions.create_region("TD_PAYLOAD", payload_size);
    memory_regions = memory_regions.create_region("TD_PAYLOAD_PAGE_TABLE", page_table_size);
    memory_regions = memory_regions.create_region("TD_PAYLOAD_MAILBOX", mailbox_size);
    memory_regions = memory_regions.create_region("TD_PAYLOAD_EVENT_LOG", event_log_size);

    memory_regions
}
