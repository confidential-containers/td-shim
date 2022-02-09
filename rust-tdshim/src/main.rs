// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![allow(unused)]
#![feature(global_asm)]
#![feature(asm)]
#![feature(alloc_error_handler)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![allow(unused_imports)]
use core::ffi::c_void;
use core::mem::size_of;
use core::panic::PanicInfo;

use r_efi::efi;
use scroll::{Pread, Pwrite};
use zerocopy::{AsBytes, ByteSlice, FromBytes};

use rust_tdshim::event_log::{
    self, TdHandoffTable, TdHandoffTablePointers, EV_EFI_HANDOFF_TABLES2, EV_PLATFORM_CONFIG_FLAGS,
    TD_LOG_EFI_HANDOFF_TABLE_GUID,
};
use rust_tdshim::{
    acpi, HobTemplate, PayloadInfo, TD_HOB_ACPI_TABLE_GUID, TD_HOB_KERNEL_INFO_GUID,
};
use td_layout::build_time::{self, *};
use td_layout::memslice;
use td_layout::runtime::{self, *};
use td_layout::RuntimeMemoryLayout;
use uefi_pi::{fv, hob, pi};

use crate::acpi::GenericSdtHeader;
use crate::tcg::TdEventLog;
#[cfg(feature = "secure-boot")]
use crate::verifier::PayloadVerifier;

mod asm;
mod e820;
mod heap;
mod ipl;
mod linux;
mod memory;
mod mp;
mod stack_guard;
mod tcg;
mod td;

#[cfg(feature = "cet-ss")]
mod cet_ss;
#[cfg(feature = "secure-boot")]
mod verifier;

extern "win64" {
    fn switch_stack_call(entry_point: usize, stack_top: usize, P1: usize, P2: usize);
}

#[cfg(not(test))]
#[panic_handler]
#[allow(clippy::empty_loop)]
fn panic(_info: &PanicInfo) -> ! {
    log::info!("panic ... {:?}\n", _info);
    panic!("deadloop");
}

#[cfg(not(test))]
#[alloc_error_handler]
#[allow(clippy::empty_loop)]
fn alloc_error(_info: core::alloc::Layout) -> ! {
    log::info!("alloc_error ... {:?}\n", _info);
    panic!("deadloop");
}

/// Main entry point of the td-shim, and the bootstrap code should jump here.
///
/// The bootstrap should prepare the context to satisfy `_start()`'s expectation:
/// - the memory is in 1:1 identity mapping mode with paging enabled
/// - the stack is ready for use
///
/// # Arguments
/// - `boot_fv`: pointer to the boot firmware volume
/// - `top_of_start`: top address of the stack
/// - `init_vp`: [31:0] TDINITVP - Untrusted Configuration
/// - `info`: [6:0] CPU supported GPA width, [7:7] 5 level page table support, [23:16] VCPUID,
///           [32:24] VCPU_Index
#[cfg(not(test))]
#[no_mangle]
#[export_name = "efi_main"]
pub extern "win64" fn _start(
    boot_fv: *const c_void,
    top_of_stack: *const c_void,
    init_vp: *const c_void,
    info: usize,
) -> ! {
    // The bootstrap code has setup the stack, but only the stack is available now...
    let _ = td_logger::init();
    log::info!("Starting RUST Based TdShim boot_fv - {:p}, Top of stack - {:p}, init_vp - {:p}, info - 0x{:x} \n",
               boot_fv, top_of_stack, init_vp, info);
    td_exception::setup_exception_handlers();
    log::info!("setup_exception_handlers done\n");

    // First initialize the heap allocator so that we have a normal rust world to live in...
    heap::init();

    // Get HOB list
    let hob_list = memslice::get_mem_slice(memslice::SliceType::ShimHob);
    let hob_size = hob::get_hob_total_size(hob_list).expect("failed to get size of hob list");
    let hob_list = &hob_list[0..hob_size];
    hob::dump_hob(hob_list);

    // Initialize memory subsystem.
    let num_vcpus = td::get_num_vcpus();
    accept_memory_resources(hob_list, num_vcpus);
    td_paging::init();
    let memory_top_below_4gb = hob::get_system_memory_size_below_4gb(hob_list)
        .expect("failed to figure out memory below 4G from hob list");
    let runtime_memory_layout = RuntimeMemoryLayout::new(memory_top_below_4gb);
    let memory_all = memory::get_memory_size(hob_list);
    let mut mem = memory::Memory::new(&runtime_memory_layout, memory_all);
    mem.setup_paging();

    // Set up the TD event log buffer.
    // Safe because it's used to initialize the EventLog subsystem which ensures safety.
    let event_log_buf = unsafe {
        memslice::get_dynamic_mem_slice_mut(
            memslice::SliceType::EventLog,
            runtime_memory_layout.runtime_event_log_base as usize,
        )
    };
    let mut td_event_log = tcg::TdEventLog::new(event_log_buf);
    log_hob_list(hob_list, &mut td_event_log);

    // If the Kernel Information GUID HOB is present, try to boot the Linux kernel.
    if let Some(kernel_hob) = hob::get_next_extension_guid_hob(hob_list, &TD_HOB_KERNEL_INFO_GUID) {
        boot_linux_kernel(
            kernel_hob,
            hob_list,
            &runtime_memory_layout,
            &mut td_event_log,
            num_vcpus,
        );
    }

    // Get and parse image file from the payload firmware volume.
    let fv_buffer = memslice::get_mem_slice(memslice::SliceType::ShimPayload);
    let mut payload = fv::get_image_from_fv(
        fv_buffer,
        pi::fv::FV_FILETYPE_DXE_CORE,
        pi::fv::SECTION_PE32,
    )
    .expect("Failed to get image file from Firmware Volume");
    let (entry, basefw, basefwsize) =
        ipl::find_and_report_entry_point(&mut mem, payload).expect("Entry point not found!");
    let entry = entry as usize;

    // Initialize the stack to run the image
    stack_guard::stack_guard_enable(&mut mem);
    #[cfg(feature = "cet-ss")]
    cet_ss::enable_cet_ss(
        runtime_memory_layout.runtime_shadow_stack_base,
        runtime_memory_layout.runtime_shadow_stack_top,
    );
    let stack_top =
        (runtime_memory_layout.runtime_stack_base + TD_PAYLOAD_STACK_SIZE as u64) as usize;

    // Prepare the HOB list to run the image
    let hob_base = prepare_hob_list(
        hob_list,
        &runtime_memory_layout,
        &mut td_event_log,
        payload,
        basefw,
        basefwsize,
        memory_top_below_4gb,
    );

    // Finally let's switch stack and jump to the image entry point...
    log::info!(
        " start launching payload {:p} and switch stack {:p}...\n",
        entry as *const usize,
        stack_top as *const usize
    );
    unsafe { switch_stack_call(entry, stack_top, hob_base as usize, 0) };
    panic!("payload entry() should not return here, deadloop!!!");
}

fn log_hob_list(hob_list: &[u8], td_event_log: &mut tcg::TdEventLog) {
    let hand_off_table_pointers = TdHandoffTablePointers {
        table_descripion_size: 8,
        table_description: [b't', b'd', b'_', b'h', b'o', b'b', 0, 0],
        number_of_tables: 1,
        table_entry: [TdHandoffTable {
            guid: TD_LOG_EFI_HANDOFF_TABLE_GUID,
            table: hob_list as *const _ as *const c_void as u64,
        }],
    };
    let mut tdx_handofftable_pointers_buffer = [0u8; size_of::<TdHandoffTablePointers>()];

    tdx_handofftable_pointers_buffer
        .pwrite(hand_off_table_pointers, 0)
        .expect("Failed to log HOB list to the td event log");
    td_event_log.create_event_log(
        1,
        EV_EFI_HANDOFF_TABLES2,
        &tdx_handofftable_pointers_buffer,
        hob_list,
    );
}

fn accept_memory_resources(hob_list: &[u8], num_vcpus: u32) {
    let mut offset: usize = 0;
    loop {
        let hob = &hob_list[offset..];
        let header: pi::hob::Header = hob.pread(0).expect("Failed to read HOB header");

        match header.r#type {
            pi::hob::HOB_TYPE_RESOURCE_DESCRIPTOR => {
                let resource_hob: pi::hob::ResourceDescription = hob.pread(0).unwrap();
                if resource_hob.resource_type == pi::hob::RESOURCE_SYSTEM_MEMORY {
                    td::accept_memory_resource_range(
                        num_vcpus,
                        resource_hob.physical_start,
                        resource_hob.resource_length,
                    );
                }
            }
            pi::hob::HOB_TYPE_END_OF_HOB_LIST => {
                break;
            }
            _ => {}
        }

        offset = hob::align_to_next_hob_offset(hob_list.len(), offset, header.length)
            .expect("Failed to find next HOB entry");
    }
}

fn boot_linux_kernel(
    kernel_hob: &[u8],
    hob_list: &[u8],
    layout: &RuntimeMemoryLayout,
    td_event_log: &mut TdEventLog,
    vcpus: u32,
) {
    let kernel_info = hob::get_guid_data(kernel_hob)
        .expect("Can not fetch kernel data from the Kernel Info GUID HOB!!!");
    let vmm_kernel = kernel_info
        .pread::<PayloadInfo>(0)
        .expect("Can not fetch PayloadInfo structure from the Kernel Info GUID HOB");

    match vmm_kernel.image_type {
        0 => {}
        1 => {
            let rsdp = prepare_acpi_tables(hob_list, layout, td_event_log, vcpus);
            let e820_table = e820::create_e820_entries(layout);
            // Safe because we are handle off this buffer to linux kernel.
            let payload = unsafe { memslice::get_mem_slice_mut(memslice::SliceType::Payload) };
            linux::boot::boot_kernel(payload, rsdp, e820_table.as_slice());
            panic!("Linux kernel should not return here!!!");
        }
        _ => panic!("Unknown kernel image type {}!!!", vmm_kernel.image_type),
    }
}

// Prepare ACPI tables for the virtual machine and panics if error happens.
fn prepare_acpi_tables(
    hob_list: &[u8],
    layout: &RuntimeMemoryLayout,
    td_event_log: &mut TdEventLog,
    vcpus: u32,
) -> u64 {
    // Safe because BSP is the only active vCPU so it's single-threaded context.
    let acpi_slice = unsafe {
        memslice::get_dynamic_mem_slice_mut(
            memslice::SliceType::Acpi,
            layout.runtime_acpi_base as usize,
        )
    };
    let mut acpi_tables = acpi::AcpiTables::new(acpi_slice, acpi_slice.as_ptr() as *const _ as u64);

    let madt = mp::create_madt(vcpus as u8, build_time::TD_SHIM_MAILBOX_BASE as u64)
        .expect("Failed to create ACPI MADT table");
    acpi_tables.install(&madt.data);

    let tdel = td_event_log.create_tdel();
    acpi_tables.install(tdel.as_bytes());

    let mut next_hob = hob_list;
    while let Some(hob) = hob::get_next_extension_guid_hob(next_hob, &TD_HOB_ACPI_TABLE_GUID) {
        let table = hob::get_guid_data(hob).expect("Failed to get data from ACPI GUID HOB");
        let header = GenericSdtHeader::read_from(&table[..size_of::<GenericSdtHeader>()])
            .expect("Faile to read table header from ACPI GUID HOB");
        // Protect MADT and TDEL from overwritten by the VMM.
        if &header.signature != b"APIC" && &header.signature != b"TDEL" {
            acpi_tables.install(table);
        }
        next_hob = hob::seek_to_next_hob(hob).unwrap();
    }

    acpi_tables.finish()
}

fn prepare_hob_list(
    hob_list: &[u8],
    layout: &RuntimeMemoryLayout,
    td_event_log: &mut TdEventLog,
    mut payload: &[u8],
    basefw: u64,
    basefwsize: u64,
    memory_top_below_4gb: u64,
) -> u64 {
    let hob_base = layout.runtime_hob_base;
    let memory_bottom = layout.runtime_memory_bottom;

    let handoff_info_table = pi::hob::HandoffInfoTable {
        header: pi::hob::Header {
            r#type: pi::hob::HOB_TYPE_HANDOFF,
            length: size_of::<pi::hob::HandoffInfoTable>() as u16,
            reserved: 0,
        },
        version: 9u32,
        boot_mode: pi::boot_mode::BOOT_WITH_FULL_CONFIGURATION,
        efi_memory_top: memory_top_below_4gb,
        efi_memory_bottom: memory_bottom,
        efi_free_memory_top: memory_top_below_4gb,
        efi_free_memory_bottom: memory_bottom
            + ipl::efi_page_to_size(ipl::efi_size_to_page(size_of::<HobTemplate>() as u64)),
        efi_end_of_hob_list: hob_base + size_of::<HobTemplate>() as u64,
    };

    let cpu = pi::hob::Cpu {
        header: pi::hob::Header {
            r#type: pi::hob::HOB_TYPE_CPU,
            length: size_of::<pi::hob::Cpu>() as u16,
            reserved: 0,
        },
        size_of_memory_space: memory::cpu_get_memory_space_size(),
        size_of_io_space: 16u8,
        reserved: [0u8; 6],
    };

    let firmware_volume = pi::hob::FirmwareVolume {
        header: pi::hob::Header {
            r#type: pi::hob::HOB_TYPE_FV,
            length: size_of::<pi::hob::FirmwareVolume>() as u16,
            reserved: 0,
        },
        base_address: TD_SHIM_PAYLOAD_BASE as u64,
        length: TD_SHIM_PAYLOAD_SIZE as u64,
    };

    const MEMORY_ALLOCATION_STACK_GUID: efi::Guid = efi::Guid::from_fields(
        0x4ED4BF27,
        0x4092,
        0x42E9,
        0x80,
        0x7D,
        &[0x52, 0x7B, 0x1D, 0x00, 0xC9, 0xBD],
    );
    let stack = pi::hob::MemoryAllocation {
        header: pi::hob::Header {
            r#type: pi::hob::HOB_TYPE_MEMORY_ALLOCATION,
            length: size_of::<pi::hob::MemoryAllocation>() as u16,
            reserved: 0,
        },
        alloc_descriptor: pi::hob::MemoryAllocationHeader {
            name: *MEMORY_ALLOCATION_STACK_GUID.as_bytes(),
            memory_base_address: layout.runtime_stack_base,
            memory_length: TD_PAYLOAD_STACK_SIZE as u64
                - (stack_guard::STACK_GUARD_PAGE_SIZE + stack_guard::STACK_EXCEPTION_PAGE_SIZE)
                    as u64,
            memory_type: efi::MemoryType::BootServicesData as u32,
            reserved: [0u8; 4],
        },
    };

    // Enable host Paging
    const PAGE_TABLE_NAME_GUID: efi::Guid = efi::Guid::from_fields(
        0xF8E21975,
        0x0899,
        0x4F58,
        0xA4,
        0xBE,
        &[0x55, 0x25, 0xA9, 0xC6, 0xD7, 0x7A],
    );

    let page_table = pi::hob::MemoryAllocation {
        header: pi::hob::Header {
            r#type: pi::hob::HOB_TYPE_MEMORY_ALLOCATION,
            length: size_of::<pi::hob::MemoryAllocation>() as u16,
            reserved: 0,
        },
        alloc_descriptor: pi::hob::MemoryAllocationHeader {
            name: *PAGE_TABLE_NAME_GUID.as_bytes(),
            memory_base_address: TD_PAYLOAD_PAGE_TABLE_BASE,
            memory_length: td_paging::PAGE_TABLE_SIZE as u64,
            memory_type: efi::MemoryType::BootServicesData as u32,
            reserved: [0u8; 4],
        },
    };

    let lowmemory = hob::get_system_memory_size_below_4gb(hob_list).unwrap();

    let memory_above_1m = pi::hob::ResourceDescription {
        header: pi::hob::Header {
            r#type: pi::hob::HOB_TYPE_RESOURCE_DESCRIPTOR,
            length: size_of::<pi::hob::ResourceDescription>() as u16,
            reserved: 0,
        },
        owner: *efi::Guid::from_fields(
            0x4ED4BF27,
            0x4092,
            0x42E9,
            0x80,
            0x7D,
            &[0x52, 0x7B, 0x1D, 0x00, 0xC9, 0xBD],
        )
        .as_bytes(),
        resource_type: pi::hob::RESOURCE_SYSTEM_MEMORY,
        resource_attribute: pi::hob::RESOURCE_ATTRIBUTE_PRESENT
            | pi::hob::RESOURCE_ATTRIBUTE_INITIALIZED
            | pi::hob::RESOURCE_ATTRIBUTE_UNCACHEABLE
            | pi::hob::RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE
            | pi::hob::RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE
            | pi::hob::RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE
            | pi::hob::RESOURCE_ATTRIBUTE_TESTED,
        physical_start: 0x100000u64,
        resource_length: lowmemory - 0x100000u64,
    };

    let memory_below_1m = pi::hob::ResourceDescription {
        header: pi::hob::Header {
            r#type: pi::hob::HOB_TYPE_RESOURCE_DESCRIPTOR,
            length: size_of::<pi::hob::ResourceDescription>() as u16,
            reserved: 0,
        },
        owner: *efi::Guid::from_fields(
            0x4ED4BF27,
            0x4092,
            0x42E9,
            0x80,
            0x7D,
            &[0x52, 0x7B, 0x1D, 0x00, 0xC9, 0xBD],
        )
        .as_bytes(),
        resource_type: pi::hob::RESOURCE_SYSTEM_MEMORY,
        resource_attribute: pi::hob::RESOURCE_ATTRIBUTE_PRESENT
            | pi::hob::RESOURCE_ATTRIBUTE_INITIALIZED
            | pi::hob::RESOURCE_ATTRIBUTE_UNCACHEABLE
            | pi::hob::RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE
            | pi::hob::RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE
            | pi::hob::RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE
            | pi::hob::RESOURCE_ATTRIBUTE_TESTED,
        physical_start: 0u64,
        resource_length: 0x80000u64 + 0x20000u64,
    };

    #[cfg(feature = "secure-boot")]
    {
        let cfv = memslice::get_mem_slice(memslice::SliceType::Config);
        let verifier = verifier::PayloadVerifier::new(payload, cfv);
        if let Ok(verifier) = &verifier {
            td_event_log.create_event_log(
                4,
                EV_PLATFORM_CONFIG_FLAGS,
                b"td payload",
                verifier::PayloadVerifier::get_trust_anchor(cfv).unwrap(),
            );
            verifier.verify().expect("Verification fails");
            td_event_log.create_event_log(4, EV_PLATFORM_CONFIG_FLAGS, b"td payload", payload);
            td_event_log.create_event_log(
                4,
                EV_PLATFORM_CONFIG_FLAGS,
                b"td payload svn",
                &u64::to_le_bytes(verifier.get_payload_svn()),
            );
            // Parse out the image from signed payload
            payload = verifier::PayloadVerifier::get_payload_image(payload).unwrap();
        } else {
            panic!("Secure Boot: Cannot read verify header from payload binary");
        }
    }

    const PAYLOAD_NAME_GUID: efi::Guid = efi::Guid::from_fields(
        0x6948d4a,
        0xd359,
        0x4721,
        0xad,
        0xf6,
        &[0x52, 0x25, 0x48, 0x5a, 0x6a, 0x3a],
    );

    let payload = pi::hob::MemoryAllocation {
        header: pi::hob::Header {
            r#type: pi::hob::HOB_TYPE_MEMORY_ALLOCATION,
            length: size_of::<pi::hob::MemoryAllocation>() as u16,
            reserved: 0,
        },
        alloc_descriptor: pi::hob::MemoryAllocationHeader {
            name: *PAYLOAD_NAME_GUID.as_bytes(),
            memory_base_address: basefw,
            memory_length: ipl::efi_page_to_size(ipl::efi_size_to_page(basefwsize)),
            memory_type: efi::MemoryType::BootServicesCode as u32,
            reserved: [0u8; 4],
        },
    };

    let hob_template = HobTemplate {
        handoff_info_table,
        firmware_volume,
        cpu,
        payload,
        page_table,
        stack,
        memory_above_1m,
        memory_blow_1m: memory_below_1m,
        end_off_hob: pi::hob::Header {
            r#type: pi::hob::HOB_TYPE_END_OF_HOB_LIST,
            length: size_of::<pi::hob::Header>() as u16,
            reserved: 0,
        },
    };

    // Safe because we are the only consumer.
    let hob_slice = unsafe {
        memslice::get_dynamic_mem_slice_mut(memslice::SliceType::PayloadHob, hob_base as usize)
    };
    let _res = hob_slice.pwrite(hob_template, 0);

    hob_base
}
