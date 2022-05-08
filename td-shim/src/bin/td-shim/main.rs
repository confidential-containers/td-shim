// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![allow(unused)]
#![feature(alloc_error_handler)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![allow(unused_imports)]

extern crate alloc;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::size_of;
use core::panic::PanicInfo;

use r_efi::efi;
use scroll::{Pread, Pwrite};
use zerocopy::{AsBytes, ByteSlice, FromBytes};

use td_layout::build_time::{self, *};
use td_layout::memslice;
use td_layout::runtime::{self, *};
use td_layout::RuntimeMemoryLayout;
use td_shim::acpi::GenericSdtHeader;
use td_shim::event_log::{
    self, TdHandoffTable, TdHandoffTablePointers, EV_EFI_HANDOFF_TABLES2, EV_PLATFORM_CONFIG_FLAGS,
    TD_LOG_EFI_HANDOFF_TABLE_GUID,
};
use td_shim::{
    speculation_barrier, PayloadInfo, TdKernelInfoHobType, TD_ACPI_TABLE_HOB_GUID,
    TD_KERNEL_INFO_HOB_GUID,
};
use td_uefi_pi::{fv, hob, pi};

use crate::tcg::TdEventLog;
use crate::td_hob::TdHobInfo;

mod acpi;
mod asm;
mod e820;
mod heap;
mod ipl;
mod linux;
mod memory;
mod mp;
mod payload_hob;
mod stack_guard;
mod tcg;
mod td;
mod td_hob;

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
    let hob_list =
        TdHobInfo::check_hob_integrity(memslice::get_mem_slice(memslice::SliceType::TdHob))
            .expect("Integrity check failed: invalid HOB list");
    hob::dump_hob(hob_list);
    let mut td_hob_info =
        TdHobInfo::read_from_hob(hob_list).expect("Error occurs reading from VMM HOB");

    // Initialize memory subsystem.
    let mut mem = memory::Memory::new(&td_hob_info.memory)
        .expect("Unable to find a piece of suitable memory for runtime");
    let num_vcpus = td::get_num_vcpus();
    #[cfg(feature = "tdx")]
    mem.accept_memory_resources(num_vcpus);
    mem.setup_paging();

    // Relocate Mailbox along side with the AP function
    td::relocate_mailbox(mem.layout.runtime_mailbox_base as u32);

    // Set up the TD event log buffer.
    // Safe because it's used to initialize the EventLog subsystem which ensures safety.
    let event_log_buf = unsafe {
        memslice::get_dynamic_mem_slice_mut(
            memslice::SliceType::EventLog,
            mem.layout.runtime_event_log_base as usize,
        )
    };
    let mut td_event_log = tcg::TdEventLog::new(event_log_buf);
    log_hob_list(hob_list, &mut td_event_log);

    //Create MADT and TDEL
    let (madt, tdel) = prepare_acpi_tables(
        &mut td_hob_info.acpi_tables,
        &mem.layout,
        &mut td_event_log,
        num_vcpus,
    );
    td_hob_info.acpi_tables.push(madt.as_bytes());
    td_hob_info.acpi_tables.push(tdel.as_bytes());

    // If the Payload Information GUID HOB is present, try to boot the Linux kernel.
    if let Some(payload_info) = td_hob_info.payload_info {
        boot_linux_kernel(
            &payload_info,
            &td_hob_info.acpi_tables,
            &mem,
            &mut td_event_log,
            num_vcpus,
        );
    }

    boot_builtin_payload(&mut mem, &mut td_event_log, &td_hob_info.acpi_tables);

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

fn boot_linux_kernel(
    kernel_info: &PayloadInfo,
    acpi_tables: &Vec<&[u8]>,
    mem: &memory::Memory,
    td_event_log: &mut TdEventLog,
    vcpus: u32,
) {
    let image_type = TdKernelInfoHobType::from(kernel_info.image_type);
    match image_type {
        TdKernelInfoHobType::ExecutablePayload => return,
        TdKernelInfoHobType::BzImage | TdKernelInfoHobType::RawVmLinux => {}
        _ => panic!("Unknown kernel image type {}!!!", kernel_info.image_type),
    };

    let rsdp = install_acpi_tables(acpi_tables, &mem.layout);
    let e820_table = mem.create_e820();
    log::info!("e820 table: {:x?}\n", e820_table.as_slice());
    // Safe because we are handle off this buffer to linux kernel.
    let payload = unsafe { memslice::get_mem_slice_mut(memslice::SliceType::Payload) };

    linux::boot::boot_kernel(payload, rsdp, e820_table.as_slice(), kernel_info);
    panic!("Linux kernel should not return here!!!");
}

fn boot_builtin_payload(
    mem: &mut memory::Memory,
    td_event_log: &mut TdEventLog,
    acpi_tables: &Vec<&[u8]>,
) {
    // Get and parse image file from the payload firmware volume.
    let fv_buffer = memslice::get_mem_slice(memslice::SliceType::ShimPayload);
    let mut payload = fv::get_image_from_fv(
        fv_buffer,
        pi::fv::FV_FILETYPE_DXE_CORE,
        pi::fv::SECTION_PE32,
    )
    .expect("Failed to get image file from Firmware Volume");

    #[cfg(feature = "secure-boot")]
    {
        payload = secure_boot_verify_payload(payload, td_event_log);
    }

    let (entry, basefw, basefwsize) =
        ipl::find_and_report_entry_point(mem, payload).expect("Entry point not found!");
    let entry = entry as usize;

    // Initialize the stack to run the image
    stack_guard::stack_guard_enable(mem);
    #[cfg(feature = "cet-ss")]
    cet_ss::enable_cet_ss(
        mem.layout.runtime_shadow_stack_base,
        mem.layout.runtime_shadow_stack_top,
    );
    let stack_top = (mem.layout.runtime_stack_base + TD_PAYLOAD_STACK_SIZE as u64) as usize;

    // Prepare the HOB list to run the image
    payload_hob::build_payload_hob(acpi_tables, &mem).expect("Fail to create payload HOB");

    // Finally let's switch stack and jump to the image entry point...
    log::info!(
        " start launching payload {:p} and switch stack {:p}...\n",
        entry as *const usize,
        stack_top as *const usize
    );
    unsafe { switch_stack_call(entry, stack_top, mem.layout.runtime_hob_base as usize, 0) };
}

// Install ACPI tables into ACPI reclaimable memory for the virtual machine
// and panics if error happens.
fn install_acpi_tables(acpi_tables: &Vec<&[u8]>, layout: &RuntimeMemoryLayout) -> u64 {
    // Safe because BSP is the only active vCPU so it's single-threaded context.
    let acpi_slice = unsafe {
        memslice::get_dynamic_mem_slice_mut(
            memslice::SliceType::Acpi,
            layout.runtime_acpi_base as usize,
        )
    };
    let mut acpi = acpi::AcpiTables::new(acpi_slice, acpi_slice.as_ptr() as *const _ as u64);

    for &table in acpi_tables {
        acpi.install(table);
    }

    acpi.finish()
}

// Prepare ACPI tables for payload and panic if error happens
fn prepare_acpi_tables(
    acpi_tables: &mut Vec<&[u8]>,
    layout: &RuntimeMemoryLayout,
    td_event_log: &mut TdEventLog,
    vcpus: u32,
) -> (mp::Madt, event_log::Tdel) {
    let mut vmm_madt = None;
    let mut idx = 0;
    while idx < acpi_tables.len() {
        let table = acpi_tables[idx];
        if table.len() < size_of::<GenericSdtHeader>() {
            panic!("Invalid ACPI table HOB\n");
        }
        speculation_barrier();

        let header = GenericSdtHeader::read_from(&table[..size_of::<GenericSdtHeader>()])
            .expect("Faile to read table header from ACPI GUID HOB");
        if table.len() < header.length as usize {
            panic!("Invalid ACPI table length\n");
        }
        speculation_barrier();

        if &header.signature == b"APIC" {
            vmm_madt = Some(table);
            acpi_tables.remove(idx);
        }
        idx += 1;
    }

    let madt = if let Some(vmm_madt) = vmm_madt {
        mp::create_madt(vmm_madt, layout.runtime_mailbox_base as u64)
            .expect("Failed to create ACPI MADT table")
    } else {
        mp::create_madt_default(vcpus, layout.runtime_mailbox_base as u64)
            .expect("Failed to create ACPI MADT table")
    };

    let tdel = td_event_log.create_tdel();

    (madt, tdel)
}

#[cfg(feature = "secure-boot")]
fn secure_boot_verify_payload<'a>(payload: &'a [u8], td_event_log: &mut TdEventLog) -> &'a [u8] {
    let cfv = memslice::get_mem_slice(memslice::SliceType::Config);
    let verifier = verifier::PayloadVerifier::new(payload, cfv)
        .expect("Secure Boot: Cannot read verify header from payload binary");

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
    return verifier::PayloadVerifier::get_payload_image(payload)
        .expect("Unable to get payload image from signed binary");
}
