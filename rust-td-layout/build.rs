// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[allow(dead_code)]
#[path = "src/metadata.rs"]
mod metadata;
use crate::metadata::*;

use core::mem::size_of;
use serde::Deserialize;
use std::env;
use std::io::{Read, Write};
use std::path::Path;
use std::{fs, fs::File};

macro_rules! BUILD_TIME_TEMPLATE {
    () => {
"// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

/*
    Image Layout:
                  Binary                       Address
            {config_offset:#010X} -> +--------------+ <-  {config_base:#010X}
                          |     VAR      |
            {mailbox_offset:#010X} -> +--------------+ <-  {mailbox_base:#010X}
                          |  TD_MAILBOX  |
            {hob_offset:#010X} -> +--------------+ <-  {hob_base:#010X}
                          |    TD_HOB    |
            {temp_stack_offset:#010X} -> +--------------+ <-  {temp_stack_base:#010X}
                          |    (Guard)   |
                          |  TEMP_STACK  |
            {temp_heap_offset:#010X} -> +--------------+ <-  {temp_heap_base:#010X}
                          |   TEMP_RAM   |
            {payload_offset:#010X} -> +--------------+ <-  {payload_base:#010X}
           ({payload_size:#010X})   | Rust Payload |
                          |     (pad)    |
                          |   metadata   |
            {ipl_offset:#010X} -> +--------------+ <-  {ipl_base:#010X}
           ({ipl_size:#010X})   |   Rust IPL   |
                          |     (pad)    |
            {rst_vec_offset:#010X} -> +--------------+ <-  {rst_vec_base:#010X}
           ({rst_vec_size:#010X})   | Reset Vector |
            {firmware_size:#010X} -> +--------------+ <- 0x100000000 (4G)
*/

// Image
pub const TD_SHIM_CONFIG_OFFSET: u32 = {config_offset:#X};
pub const TD_SHIM_CONFIG_SIZE: u32 = {config_size:#X};
pub const TD_SHIM_MAILBOX_OFFSET: u32 = {mailbox_offset:#X}; // TD_SHIM_CONFIG_OFFSET + TD_SHIM_CONFIG_SIZE
pub const TD_SHIM_MAILBOX_SIZE: u32 = {mailbox_size:#X};
pub const TD_SHIM_HOB_OFFSET: u32 = {hob_offset:#X}; // TD_SHIM_MAILBOX_OFFSET + TD_SHIM_MAILBOX_SIZE
pub const TD_SHIM_HOB_SIZE: u32 = {hob_size:#X};
pub const TD_SHIM_TEMP_STACK_GUARD_SIZE: u32 = {temp_stack_guard_size:#X};
pub const TD_SHIM_TEMP_STACK_OFFSET: u32 = {temp_stack_offset:#X}; // TD_SHIM_HOB_OFFSET + TD_SHIM_HOB_SIZE + TD_SHIM_TEMP_STACK_GUARD_SIZE
pub const TD_SHIM_TEMP_STACK_SIZE: u32 = {temp_stack_size:#X};
pub const TD_SHIM_TEMP_HEAP_OFFSET: u32 = {temp_heap_offset:#X}; // TD_SHIM_TEMP_STACK_OFFSET + TD_SHIM_TEMP_STACK_SIZE
pub const TD_SHIM_TEMP_HEAP_SIZE: u32 = {temp_heap_size:#X};

pub const TD_SHIM_PAYLOAD_OFFSET: u32 = {payload_offset:#X}; // TD_SHIM_TEMP_HEAP_OFFSET + TD_SHIM_TEMP_HEAP_SIZE
pub const TD_SHIM_PAYLOAD_SIZE: u32 = {payload_size:#X};
pub const TD_SHIM_IPL_OFFSET: u32 = {ipl_offset:#X}; // TD_SHIM_PAYLOAD_OFFSET + TD_SHIM_PAYLOAD_SIZE
pub const TD_SHIM_METADATA_OFFSET: u32 = {metadata_offset:#X}; // TD_SHIM_IPL_OFFSET - size_of::<TdxMetadata>() + size_of::<TdxMetadataGuid>()
pub const TD_SHIM_IPL_SIZE: u32 = {ipl_size:#X};
pub const TD_SHIM_RESET_VECTOR_OFFSET: u32 = {rst_vec_offset:#X}; // TD_SHIM_IPL_OFFSET + TD_SHIM_IPL_SIZE
pub const TD_SHIM_RESET_VECTOR_SIZE: u32 = {rst_vec_size:#X};
pub const TD_SHIM_FIRMWARE_SIZE: u32 = {firmware_size:#X}; // TD_SHIM_RESET_VECTOR_OFFSET + TD_SHIM_RESET_VECTOR_SIZE

// Image loaded
pub const TD_SHIM_FIRMWARE_BASE: u32 = {firmware_base:#X}; // 0xFFFFFFFF - TD_SHIM_FIRMWARE_SIZE + 1
pub const TD_SHIM_CONFIG_BASE: u32 = {config_base:#X}; // TD_SHIM_FIRMWARE_BASE + TD_SHIM_CONFIG_OFFSET
pub const TD_SHIM_MAILBOX_BASE: u32 = {mailbox_base:#X}; // TD_SHIM_FIRMWARE_BASE + TD_SHIM_MAILBOX_OFFSET
pub const TD_SHIM_HOB_BASE: u32 = {hob_base:#X}; // TD_SHIM_FIRMWARE_BASE + TD_SHIM_HOB_OFFSET
pub const TD_SHIM_TEMP_STACK_BASE: u32 = {temp_stack_base:#X}; // TD_SHIM_FIRMWARE_BASE + TD_SHIM_TEMP_STACK_OFFSET
pub const TD_SHIM_TEMP_HEAP_BASE: u32 = {temp_heap_base:#X}; // TD_SHIM_FIRMWARE_BASE + TD_SHIM_TEMP_HEAP_OFFSET
pub const TD_SHIM_PAYLOAD_BASE: u32 = {payload_base:#X}; // TD_SHIM_FIRMWARE_BASE + TD_SHIM_PAYLOAD_OFFSET
pub const TD_SHIM_IPL_BASE: u32 = {ipl_base:#X}; // TD_SHIM_FIRMWARE_BASE + TD_SHIM_IPL_OFFSET
pub const TD_SHIM_RESET_VECTOR_BASE: u32 = {rst_vec_base:#X}; // TD_SHIM_FIRMWARE_BASE + TD_SHIM_RESET_VECTOR_OFFSET
pub const TD_SHIM_RESET_SEC_CORE_ENTRY_POINT_ADDR: u32 = {sec_entry_point:#X}; // 0xFFFFFFFF - 0x20 - 12 + 1
pub const TD_SHIM_RESET_SEC_CORE_BASE_ADDR: u32 = {sec_core_base:#X}; // 0xFFFFFFFF - 0x20 - 8 + 1
pub const TD_SHIM_RESET_SEC_CORE_SIZE_ADDR: u32 = {sec_core_size:#X}; // 0xFFFFFFFF - 0x20 - 4 + 1
"
};
}

macro_rules! RUNTIME_TEMPLATE {
    () => {
        "// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

/*
    Mem Layout:
                                            Address
                    +--------------+ <-  0x0
                    |     Legacy   |
                    +--------------+ <-  0x00100000 (1M)
                    |   ........   |
                    +--------------+ <-  {pt_base:#010X}
                    |  Page Table  |
                    +--------------+ <-  {payload_param_base:#010X}
                    | PAYLOAD PARAM|    ({payload_param_size:#010X})
                    +--------------+ <-  {payload_base:#010X}
                    |    PAYLOAD   |    ({payload_size:#010X})
                    +--------------+
                    |   ........   |
                    +--------------+ <-  {dma_base:#010X}
                    |     DMA      |    ({dma_size:#010X})
                    +--------------+ <-  {heap_base:#010X}
                    |     HEAP     |    ({heap_size:#010X})
                    +--------------+ <-  {stack_base:#010X}
                    |     STACK    |    ({stack_size:#010X})
                    +--------------+ <-  {shadow_stack_base:#010X}
                    |      SS      |    ({shadow_stack_size:#010X})
                    +--------------+ <-  {hob_base:#010X}
                    |    TD_HOB    |    ({hob_size:#010X})
                    +--------------+ <-  {acpi_base:#010X}
                    |     ACPI     |    ({acpi_size:#010X})
                    +--------------+ <-  {event_log_base:#010X}
                    | TD_EVENT_LOG |    ({event_log_size:#010X})
                    +--------------+ <-  0x80000000 (2G) - for example
*/

pub const TD_PAYLOAD_EVENT_LOG_SIZE: u32 = {event_log_size:#X};
pub const TD_PAYLOAD_ACPI_SIZE: u32 = {acpi_size:#X};
pub const TD_PAYLOAD_HOB_SIZE: u32 = {hob_size:#X};
pub const TD_PAYLOAD_SHADOW_STACK_SIZE: u32 = {shadow_stack_size:#X};
pub const TD_PAYLOAD_STACK_SIZE: u32 = {stack_size:#X};
pub const TD_PAYLOAD_HEAP_SIZE: usize = {heap_size:#X};
pub const TD_PAYLOAD_DMA_SIZE: usize = {dma_size:#X};

pub const TD_PAYLOAD_PAGE_TABLE_BASE: u64 = {pt_base:#X};
pub const TD_PAYLOAD_PARAM_BASE: u64 = {payload_param_base:#X};
pub const TD_PAYLOAD_PARAM_SIZE: u64 = {payload_param_size:#X};
pub const TD_PAYLOAD_BASE: u64 = {payload_base:#X};
pub const TD_PAYLOAD_SIZE: usize = {payload_size:#X};
"
    };
}

#[derive(Debug, PartialEq, Deserialize)]
struct TdLayoutConfig {
    image_layout: TdImageLayoutConfig,
    runtime_layout: TdRuntimeLayoutConfig,
}

#[derive(Debug, PartialEq, Deserialize)]
struct TdImageLayoutConfig {
    config_offset: u32,
    config_size: u32,
    mailbox_size: u32,
    hob_size: u32,
    temp_stack_guard_size: u32,
    temp_stack_size: u32,
    temp_heap_size: u32,
    payload_size: u32,
    ipl_size: u32,
    reset_vector_size: u32,
}

#[derive(Debug, PartialEq, Deserialize)]
struct TdRuntimeLayoutConfig {
    event_log_size: u32,
    acpi_size: u32,
    hob_size: u32,
    shadow_stack_size: u32,
    stack_size: u32,
    heap_size: u32,
    dma_size: u32,
    payload_size: u32,
    payload_param_base: u32,
    payload_param_size: u32,
    page_table_base: u32,
}

#[derive(Debug, Default, PartialEq)]
struct TdLayout {
    img: TdLayoutImage,
    img_loaded: TdLayoutImageLoaded,
    runtime: TdLayoutRuntime,
}

impl TdLayout {
    fn new_from_config(config: &TdLayoutConfig) -> Self {
        let img = TdLayoutImage::new_from_config(config);
        let img_loaded = TdLayoutImageLoaded::new_from_image(&img);

        TdLayout {
            img,
            img_loaded,
            runtime: TdLayoutRuntime::new_from_config(config),
        }
    }

    fn generate_build_time_rs(&self) {
        let mut to_generate = Vec::new();
        write!(
            &mut to_generate,
            BUILD_TIME_TEMPLATE!(),
            // Image
            config_offset = self.img.config_offset,
            config_size = self.img.config_size,
            mailbox_offset = self.img.mailbox_offset,
            mailbox_size = self.img.mailbox_size,
            hob_offset = self.img.hob_offset,
            hob_size = self.img.hob_size,
            temp_stack_guard_size = self.img.temp_stack_guard_size,
            temp_stack_offset = self.img.temp_stack_offset,
            temp_stack_size = self.img.temp_stack_size,
            temp_heap_offset = self.img.temp_heap_offset,
            temp_heap_size = self.img.temp_heap_size,
            payload_offset = self.img.payload_offset,
            payload_size = self.img.payload_size,
            ipl_offset = self.img.ipl_offset,
            metadata_offset = self.img.metadata_offset,
            ipl_size = self.img.ipl_size,
            rst_vec_offset = self.img.rst_vec_offset,
            rst_vec_size = self.img.rst_vec_size,
            firmware_size = self.img.firmware_size,
            // Image loaded
            firmware_base = self.img_loaded.firmware_base,
            config_base = self.img_loaded.config_base,
            mailbox_base = self.img_loaded.mailbox_base,
            hob_base = self.img_loaded.hob_base,
            temp_stack_base = self.img_loaded.temp_stack_base,
            temp_heap_base = self.img_loaded.temp_heap_base,
            payload_base = self.img_loaded.payload_base,
            ipl_base = self.img_loaded.ipl_base,
            rst_vec_base = self.img_loaded.rst_vec_base,
            sec_entry_point = self.img_loaded.sec_entry_point,
            sec_core_base = self.img_loaded.sec_core_base,
            sec_core_size = self.img_loaded.sec_core_size,
        )
        .expect("Failed to generate configuration code from the template and JSON config");

        let dest_path = Path::new(TD_LAYOUT_CONFIG_RS_OUT_DIR).join(TD_LAYOUT_BUILD_TIME_RS_OUT);
        fs::write(&dest_path, to_generate).unwrap();
    }

    fn generate_runtime_rs(&self) {
        let mut to_generate = Vec::new();
        write!(
            &mut to_generate,
            RUNTIME_TEMPLATE!(),
            pt_base = self.runtime.pt_base,
            payload_base = self.runtime.payload_base,
            payload_size = self.runtime.payload_size,
            dma_base = self.runtime.dma_base,
            dma_size = self.runtime.dma_size,
            heap_base = self.runtime.heap_base,
            heap_size = self.runtime.heap_size,
            stack_base = self.runtime.stack_base,
            stack_size = self.runtime.stack_size,
            shadow_stack_base = self.runtime.shadow_stack_base,
            shadow_stack_size = self.runtime.shadow_stack_size,
            hob_base = self.runtime.hob_base,
            hob_size = self.runtime.hob_size,
            event_log_base = self.runtime.event_log_base,
            event_log_size = self.runtime.event_log_size,
            acpi_base = self.runtime.acpi_base,
            acpi_size = self.runtime.acpi_size,
            payload_param_base = self.runtime.payload_param_base,
            payload_param_size = self.runtime.payload_param_size,
        )
        .expect("Failed to generate configuration code from the template and JSON config");

        let dest_path = Path::new(TD_LAYOUT_CONFIG_RS_OUT_DIR).join(TD_LAYOUT_RUNTIME_RS_OUT);
        fs::write(&dest_path, to_generate).unwrap();
    }
}

#[derive(Debug, Default, PartialEq)]
struct TdLayoutImage {
    config_offset: u32,
    config_size: u32,
    mailbox_offset: u32,
    mailbox_size: u32,
    hob_offset: u32,
    hob_size: u32,
    temp_stack_guard_size: u32,
    temp_stack_offset: u32,
    temp_stack_size: u32,
    temp_heap_offset: u32,
    temp_heap_size: u32,
    payload_offset: u32,
    payload_size: u32,
    ipl_offset: u32,
    metadata_offset: u32,
    ipl_size: u32,
    rst_vec_offset: u32,
    rst_vec_size: u32,
    firmware_size: u32,
}

impl TdLayoutImage {
    fn new_from_config(config: &TdLayoutConfig) -> Self {
        let mailbox_offset = config.image_layout.config_offset + config.image_layout.config_size;
        let hob_offset = mailbox_offset + config.image_layout.mailbox_size;
        let temp_stack_offset =
            hob_offset + config.image_layout.hob_size + config.image_layout.temp_stack_guard_size;
        let temp_heap_offset = temp_stack_offset + config.image_layout.temp_stack_size;
        let payload_offset = temp_heap_offset + config.image_layout.temp_heap_size;
        let ipl_offset = payload_offset + config.image_layout.payload_size;
        let metadata_offset =
            ipl_offset - size_of::<TdxMetadata>() as u32 + size_of::<TdxMetadataGuid>() as u32;

        let rst_vec_offset = ipl_offset + config.image_layout.ipl_size;
        let firmware_size = rst_vec_offset + config.image_layout.reset_vector_size;

        TdLayoutImage {
            config_offset: config.image_layout.config_offset,
            config_size: config.image_layout.config_size,
            mailbox_offset,
            mailbox_size: config.image_layout.mailbox_size,
            hob_offset,
            hob_size: config.image_layout.hob_size,
            temp_stack_guard_size: config.image_layout.temp_stack_guard_size,
            temp_stack_offset,
            temp_stack_size: config.image_layout.temp_stack_size,
            temp_heap_offset,
            temp_heap_size: config.image_layout.temp_heap_size,
            payload_offset,
            payload_size: config.image_layout.payload_size,
            ipl_offset,
            metadata_offset,
            ipl_size: config.image_layout.ipl_size,
            rst_vec_offset,
            rst_vec_size: config.image_layout.reset_vector_size,
            firmware_size,
        }
    }
}

#[derive(Debug, Default, PartialEq)]
struct TdLayoutImageLoaded {
    firmware_base: u32,
    config_base: u32,
    mailbox_base: u32,
    hob_base: u32,
    temp_stack_base: u32,
    temp_heap_base: u32,
    payload_base: u32,
    ipl_base: u32,
    rst_vec_base: u32,
    sec_entry_point: u32,
    sec_core_base: u32,
    sec_core_size: u32,
}

impl TdLayoutImageLoaded {
    fn new_from_image(img: &TdLayoutImage) -> Self {
        let firmware_base = 0xFFFFFFFF - img.firmware_size + 1;
        let config_base = firmware_base + img.config_offset;
        let mailbox_base = firmware_base + img.mailbox_offset;
        let bt_hob_base = firmware_base + img.hob_offset;
        let temp_stack_base = firmware_base + img.temp_stack_offset;
        let temp_heap_base = firmware_base + img.temp_heap_offset;
        let payload_base = firmware_base + img.payload_offset;
        let ipl_base = firmware_base + img.ipl_offset;
        let rst_vec_base = firmware_base + img.rst_vec_offset;
        let sec_entry_point = 0xFFFFFFFF - 0x20 - 12 + 1;
        let sec_core_base = 0xFFFFFFFF - 0x20 - 8 + 1;
        let sec_core_size = 0xFFFFFFFF - 0x20 - 4 + 1;

        TdLayoutImageLoaded {
            firmware_base,
            config_base,
            mailbox_base,
            hob_base: bt_hob_base,
            temp_stack_base,
            temp_heap_base,
            payload_base,
            ipl_base,
            rst_vec_base,
            sec_entry_point,
            sec_core_base,
            sec_core_size,
        }
    }
}

#[derive(Debug, Default, PartialEq)]
struct TdLayoutRuntime {
    pt_base: u32,
    payload_base: u32,
    payload_size: u32,
    payload_param_base: u32,
    payload_param_size: u32,
    dma_base: u32,
    dma_size: u32,
    heap_base: u32,
    heap_size: u32,
    stack_base: u32,
    stack_size: u32,
    shadow_stack_base: u32,
    shadow_stack_size: u32,
    hob_base: u32,
    hob_size: u32,
    event_log_base: u32,
    event_log_size: u32,
    acpi_base: u32,
    acpi_size: u32,
}

impl TdLayoutRuntime {
    fn new_from_config(config: &TdLayoutConfig) -> Self {
        let event_log_base = 0x80000000 - config.runtime_layout.event_log_size; // TODO: 0x80000000 is hardcoded LOW_MEM_TOP, to remove
        let acpi_base = event_log_base - config.runtime_layout.acpi_size;
        let hob_base = acpi_base - config.runtime_layout.hob_size;
        let shadow_stack_base = hob_base - config.runtime_layout.shadow_stack_size;
        let stack_base = shadow_stack_base - config.runtime_layout.stack_size;
        let heap_base = stack_base - config.runtime_layout.heap_size;
        let dma_base = heap_base - config.runtime_layout.dma_size;
        let payload_param_base = config.runtime_layout.payload_param_base;
        let payload_base =
            config.runtime_layout.payload_param_base + config.runtime_layout.payload_param_size;

        TdLayoutRuntime {
            pt_base: config.runtime_layout.page_table_base,
            payload_base,
            payload_size: config.runtime_layout.payload_size,
            dma_base,
            dma_size: config.runtime_layout.dma_size,
            heap_base,
            heap_size: config.runtime_layout.heap_size,
            stack_base,
            stack_size: config.runtime_layout.stack_size,
            shadow_stack_base,
            shadow_stack_size: config.runtime_layout.shadow_stack_size,
            hob_base,
            hob_size: config.runtime_layout.hob_size,
            event_log_base,
            event_log_size: config.runtime_layout.event_log_size,
            acpi_base,
            acpi_size: config.runtime_layout.acpi_size,
            payload_param_base,
            payload_param_size: config.runtime_layout.payload_param_size,
        }
    }
}

const TD_LAYOUT_CONFIG_ENV: &str = "TD_LAYOUT_CONFIG";
const TD_LAYOUT_CONFIG_JSON_DEFAULT_PATH: &str = "etc/config.json";
const TD_LAYOUT_CONFIG_RS_OUT_DIR: &str = "src";
const TD_LAYOUT_BUILD_TIME_RS_OUT: &str = "build_time.rs";
const TD_LAYOUT_RUNTIME_RS_OUT: &str = "runtime.rs";

fn main() {
    // Read and parse the TD layout configuration file.
    let mut data = String::new();
    let td_layout_config_json_file_path = env::var(TD_LAYOUT_CONFIG_ENV)
        .unwrap_or_else(|_| TD_LAYOUT_CONFIG_JSON_DEFAULT_PATH.to_string());
    let mut td_layout_config_json_file = File::open(td_layout_config_json_file_path)
        .expect("The TD layout configuration file does not exist");
    td_layout_config_json_file
        .read_to_string(&mut data)
        .expect("Unable to read string");
    let td_layout_config: TdLayoutConfig =
        json5::from_str(&data).expect("It is not a valid TD layout configuration file.");

    let layout = TdLayout::new_from_config(&td_layout_config);
    // TODO: sanity checks on the layouts.

    // Generate config .rs file from the template and JSON inputs, then write to fs.
    layout.generate_build_time_rs();
    layout.generate_runtime_rs();

    // Re-run the build script if the files at the given paths or envs have changed.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../Cargo.lock");
    println!(
        "cargo:rerun-if-changed={}",
        TD_LAYOUT_CONFIG_JSON_DEFAULT_PATH
    );
    println!("cargo:rerun-if-env-changed={}", TD_LAYOUT_CONFIG_ENV);
}
