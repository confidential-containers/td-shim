// Copyright © 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_std]
#![no_main]
#![allow(unused)]
#![feature(global_asm)]
#![feature(asm)]
#![feature(alloc_error_handler)]
#![cfg_attr(test, allow(unused_imports))]
#![feature(custom_test_frameworks)]
#![test_runner(test_runner)]
#![reexport_test_harness_main = "test_main"]

#[cfg(test)]
use bootloader::{entry_point, BootInfo};

#[cfg(test)]
entry_point!(kernel_main);

#[macro_use]
extern crate alloc;

mod asm;
mod memslice;

#[cfg(test)]
use test_lib::{init_heap, panic, serial_println, test_runner};

#[cfg(feature = "benches")]
use benchmark::{BenchmarkContext, ALLOCATOR};
#[cfg(not(feature = "benches"))]
use linked_list_allocator::LockedHeap;

use core::alloc::Layout;
use rust_td_layout::runtime::*;
use uefi_pi::pi::hob_lib;

use alloc::{string::String, vec::Vec};

use core::panic::PanicInfo;

use core::ffi::c_void;

use chrono::{serde::ts_seconds, DateTime, Duration, FixedOffset, TimeZone, Utc};
use r_efi::efi::Guid;
use serde::{
    de::{value::UsizeDeserializer, Error},
    Deserialize, Deserializer, Serialize,
};

extern "win64" {
    fn stack_guard_test();

    #[cfg(feature = "cet-ss")]
    #[allow(unused)]
    fn cet_ss_test(count: usize);
}

#[cfg(not(test))]
#[panic_handler]
#[allow(clippy::empty_loop)]
fn panic(_info: &PanicInfo) -> ! {
    log::info!("panic ... {:?}\n", _info);
    loop {}
}

#[alloc_error_handler]
#[allow(clippy::empty_loop)]
fn alloc_error(_info: core::alloc::Layout) -> ! {
    log::info!("alloc_error ... {:?}\n", _info);
    panic!("deadloop");
}

#[cfg(not(test))]
#[cfg(not(feature = "benches"))]
#[global_allocator]
pub static ALLOCATOR: LockedHeap = LockedHeap::empty();

#[cfg(not(test))]
pub fn init_heap(heap_start: usize, heap_size: usize) {
    #[cfg(feature = "benches")]
    unsafe {
        log::info!("init_heap benches");
        ALLOCATOR.init(heap_start, heap_size);
    }

    #[cfg(not(feature = "benches"))]
    unsafe {
        ALLOCATOR.lock().init(heap_start, heap_size);
    }
}

#[cfg(test)]
fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    use lazy_static::__Deref;

    // turn the screen gray
    if let Some(framebuffer) = boot_info.framebuffer.as_mut() {
        for byte in framebuffer.buffer_mut() {
            *byte = 0x90;
        }
    }

    let memoryregions = boot_info.memory_regions.deref();
    let offset = boot_info.physical_memory_offset.into_option().unwrap();

    for usable in memoryregions.iter() {
        if usable.kind == bootloader::boot_info::MemoryRegionKind::Usable {
            init_heap((usable.start + offset) as usize, 0x100000);
            break;
        }
    }

    #[cfg(test)]
    test_main();

    loop {}
}

fn json_test() {
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct SerdeJsonTest {
        #[serde(with = "guid")]
        test_guid: Guid,
        #[serde(with = "range")]
        test_range_inclu: range::Range,
        #[serde(with = "range")]
        test_range_exclu: range::Range,
        #[serde(with = "range")]
        test_range_hex: range::Range,
        #[serde(with = "hex")]
        test_u32: u32,
        test_bool: bool,
        test_u16: u16,
        test_string: String,
        test_array: [u32; 5],
        //Default rfc3339 for chrono serde.
        test_time: DateTime<FixedOffset>,
        #[serde(with = "ts_seconds")]
        test_time_stamp: DateTime<Utc>,
    }

    mod guid {
        use r_efi::efi::Guid;
        use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
        pub fn serialize<S>(guid: &Guid, serialize: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let (time_low, time_mid, time_hi_and_version, clk_seq_hi_res, clk_seq_low, node) =
                guid.as_fields();
            let str = format!(
                "{:08X?}-{:04X?}-{:04X?}-{:02X?}{:02X?}-{:02X?}{:02X?}{:02X?}{:02X?}{:02X?}{:02X?}",
                time_low,
                time_mid,
                time_hi_and_version,
                clk_seq_hi_res,
                clk_seq_low,
                node[0],
                node[1],
                node[2],
                node[3],
                node[4],
                node[5]
            );
            serialize.serialize_str(&str)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Guid, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s: &str = Deserialize::deserialize(deserializer)?;
            Ok(Guid::from_fields(
                u32::from_str_radix(&s[0..8], 16).map_err(D::Error::custom)?,
                u16::from_str_radix(&s[9..13], 16).map_err(D::Error::custom)?,
                u16::from_str_radix(&s[14..18], 16).map_err(D::Error::custom)?,
                u8::from_str_radix(&s[19..21], 16).map_err(D::Error::custom)?,
                u8::from_str_radix(&s[21..23], 16).map_err(D::Error::custom)?,
                &[
                    u8::from_str_radix(&s[24..26], 16).map_err(D::Error::custom)?,
                    u8::from_str_radix(&s[26..28], 16).map_err(D::Error::custom)?,
                    u8::from_str_radix(&s[28..30], 16).map_err(D::Error::custom)?,
                    u8::from_str_radix(&s[30..32], 16).map_err(D::Error::custom)?,
                    u8::from_str_radix(&s[32..34], 16).map_err(D::Error::custom)?,
                    u8::from_str_radix(&s[34..36], 16).map_err(D::Error::custom)?,
                ],
            ))
        }
    }

    mod range {
        use alloc::string::ToString;
        use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

        pub fn new(exclusive_min: bool, min: i64, exclusive_max: bool, max: i64) -> Range {
            Range {
                exclusive_min,
                min,
                exclusive_max,
                max,
            }
        }

        #[derive(Debug, PartialEq)]
        pub struct Range {
            exclusive_min: bool,
            min: i64,
            exclusive_max: bool,
            max: i64,
        }

        pub fn serialize<S>(range: &Range, serialize: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let str = format!(
                "{}{}..{}{}",
                if range.exclusive_min { '(' } else { '[' },
                if range.min == i64::MIN {
                    "-inf".to_string()
                } else {
                    range.min.to_string()
                },
                if range.max == i64::MAX {
                    "inf".to_string()
                } else {
                    range.max.to_string()
                },
                if range.exclusive_max { ')' } else { ']' },
            );
            serialize.serialize_str(&str)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Range, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s: &str = Deserialize::deserialize(deserializer)?;
            let len = s.len();
            let exclu_max = b')' == s.as_bytes()[len - 1];
            let exclu_min = b'(' == s.as_bytes()[0];
            let dot_dot = s.find("..").unwrap();
            fn str_to_int64(s: &str) -> i64 {
                match s {
                    "-inf" => i64::MIN,
                    "inf" => i64::MAX,
                    _ => {
                        if s.len() > 2 && (&s[..2] == "0x" || &s[..2] == "0X") {
                            i64::from_str_radix(&s[2..], 16).unwrap()
                        } else {
                            s.parse::<i64>().unwrap()
                        }
                    }
                }
            }
            let min = str_to_int64(&s[1..dot_dot]);
            let max = str_to_int64(&s[dot_dot + 2..len - 1]);
            Ok(Range {
                exclusive_max: exclu_max,
                exclusive_min: exclu_min,
                min: min,
                max: max,
            })
        }
    }

    mod hex {
        use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
        pub fn serialize<S>(num: &u32, serialize: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let str = format!("0x{:x}", num);
            serialize.serialize_str(&str)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<u32, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s: &str = Deserialize::deserialize(deserializer)?;
            if s.len() > 2 && (&s[..2] == "0x" || &s[..2] == "0X") {
                u32::from_str_radix(&s[2..], 16).map_err(D::Error::custom)
            } else {
                s.parse::<u32>().map_err(D::Error::custom)
            }
        }
    }

    let zero = SerdeJsonTest {
        //{B0BAE802-534F-4974-942D-2EDE15BC1AE8}
        test_guid: Guid::from_fields(
            0xB0BAE802,
            0x534F,
            0x4974,
            0x94,
            0x2D,
            &[0x2E, 0xDE, 0x15, 0xBC, 0x1A, 0xE8],
        ),
        test_range_inclu: range::new(false, 2, true, i64::MAX),
        test_range_exclu: range::new(true, -2, true, 5),
        test_range_hex: range::new(true, 16, false, 32),
        test_u32: 0x00001000,
        test_bool: true,
        test_u16: 256,
        test_string: String::from("A test"),
        test_array: [1, 2, 3, 4, 5],
        test_time: DateTime::parse_from_rfc3339("1996-12-19T16:39:57-08:00").unwrap(),
        test_time_stamp: Utc.ymd(2015, 5, 15).and_hms(10, 0, 0),
    };

    let config = r#"
        {
            "test_guid":"B0BAE802-534F-4974-942D-2EDE15BC1AE8",
            "test_range_inclu":"[2..inf)",
            "test_range_exclu":"(-2..5)",
            "test_range_hex":"(0x10..0x20]",
            "test_u32": "0x00001000",
            "test_bool": true,
            "test_u16": 256,
            "test_string": "A test",
            "test_array": [1, 2, 3, 4, 5],
            "test_time":"1996-12-19T16:39:57-08:00",
            "test_time_stamp":1431684000
        }
    "#;
    let bytes_config = config.as_bytes();

    let one: SerdeJsonTest =
        serde_json::from_slice(bytes_config).expect("It is not a successful JSON test.");
    assert_eq!(zero, one);
}

static mut INS: [u8; 2] = [0xEB, 0xFE];

//
// This function will cause page fault by memory protection.
//
fn mp_test() {
    //Test NX on payload data sections
    unsafe {
        let address = INS.as_ptr() as u64;
        log::info!("NX test address: {:x}\n", address);
        let nx = &address as *const u64 as *const fn();
        (*nx)();
    }

    //Test NX on heap
    unsafe {
        let ins_heap: Vec<u8> = vec![0xEB, 0xFE];
        let address = ins_heap.as_ptr() as u64;
        log::info!("NX test address: {:x}\n", address);
        let nx = &address as *const u64 as *const fn();
        (*nx)();
    }

    //Test WP on a hardcode payload code section (PE)
    unsafe {
        let ptr_to_wp: *mut u32 = 0x403_3000 as *mut core::ffi::c_void as *mut u32;
        *ptr_to_wp = 0x1000;
    }
}
#[cfg(not(test))]
#[no_mangle]
#[cfg_attr(target_os = "uefi", export_name = "efi_main")]
pub extern "win64" fn _start(hob: *const c_void) -> ! {
    tdx_logger::init();
    log::info!("Starting rust-td-payload hob - {:p}\n", hob);

    log::info!("setup_exception_handlers done\n");

    // let hob_buffer = unsafe {
    //     core::slice::from_raw_parts(hob as *const u8, TD_PAYLOAD_HOB_SIZE as usize)
    // };

    let hob_buffer =
        memslice::get_dynamic_mem_slice_mut(memslice::SliceType::PayloadHob, hob as usize);

    let hob_size = hob_lib::get_hob_total_size(hob_buffer).unwrap();
    let hob_list = &hob_buffer[..hob_size];
    hob_lib::dump_hob(hob_list);

    init_heap(
        (hob_lib::get_system_memory_size_below_4gb(hob_list) as usize
            - (TD_PAYLOAD_HOB_SIZE
                + TD_PAYLOAD_STACK_SIZE
                + TD_PAYLOAD_SHADOW_STACK_SIZE
                + TD_PAYLOAD_ACPI_SIZE
                + TD_PAYLOAD_EVENT_LOG_SIZE) as usize
            - TD_PAYLOAD_HEAP_SIZE as usize),
        TD_PAYLOAD_HEAP_SIZE as usize,
    );

    let memory_layout = rust_td_layout::RuntimeMemoryLayout::new(
        hob_lib::get_system_memory_size_below_4gb(hob_list),
    );
    assert_eq!(
        (hob_lib::get_system_memory_size_below_4gb(hob_list) as usize
            - (TD_PAYLOAD_HOB_SIZE
                + TD_PAYLOAD_STACK_SIZE
                + TD_PAYLOAD_SHADOW_STACK_SIZE
                + TD_PAYLOAD_ACPI_SIZE
                + TD_PAYLOAD_EVENT_LOG_SIZE) as usize
            - TD_PAYLOAD_HEAP_SIZE as usize) as u64,
        memory_layout.runtime_heap_base
    );

    #[cfg(feature = "benches")]
    {
        let mut bench = BenchmarkContext::new(memory_layout, "test");

        bench.bench_start();

        test_stack();

        bench.bench_end();
    }

    //Dump TD Report
    tdx_tdcall::tdreport::tdreport_dump();

    //Test JSON function using no-std serd_json.
    json_test();

    //Stack guard test
    unsafe { stack_guard_test() };

    //Memory Protection (WP & NX) test.
    mp_test();

    // Cet is not enabled by vcpu for now
    #[cfg(feature = "cet-ss")]
    unsafe {
        cet_ss_test(1000)
    };

    // Test
    unsafe {
        let pointer: *const u32 = 0x10000000000usize as *const core::ffi::c_void as *const u32;
        let data = *pointer;
        log::info!("test - data: {:x}", data);
    }

    panic!("deadloop");
}

fn test_stack() {
    let mut a = [0u8; 0x3000];
    for i in a.iter_mut() {
        *i = 0xcc;
    }
    let rsp: usize;
    unsafe {
        asm!("mov {}, rsp", out(reg) rsp);
    }
    log::info!("rsp_test: {:x}\n", rsp);
    let mut b = vec![1u8, 2, 3, 4];
    log::info!("test stack!!!!!!!!\n");
    log::info!("a: {:x}\n", a.as_ptr() as usize);
    log::info!("b: {:p}\n", &b);
}

#[cfg(test)]
mod tests {

    #[test_case]
    fn trivial_assertion() {
        assert_eq!(1, 1);
    }

    #[test_case]
    fn test_json() {
        super::json_test();
    }
}
