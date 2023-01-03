// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![allow(unused)]
#![feature(alloc_error_handler)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![allow(unused_imports)]

extern crate alloc;
use acpi::Sdt;
use alloc::boxed::Box;
use alloc::vec::Vec;
use asm::{empty_exception_handler, empty_exception_handler_size};
use core::ffi::c_void;
use core::mem::size_of;
use core::panic::PanicInfo;
use td_exception::idt::{load_idtr, Idt};
use td_shim::event_log::CCEL_CC_TYPE_TDX;
use x86_64::registers::segmentation::{Segment, CS};
use x86_64::structures::DescriptorTablePointer;

use r_efi::efi;
use scroll::{Pread, Pwrite};
use zerocopy::{AsBytes, ByteSlice, FromBytes};

use cc_measurement::{log::CcEventLogWriter, EV_EFI_HANDOFF_TABLES2, EV_PLATFORM_CONFIG_FLAGS};
use td_layout::build_time::{self, *};
use td_layout::memslice;
use td_layout::runtime::{self, *};
use td_layout::RuntimeMemoryLayout;
use td_shim::acpi::{Ccel, GenericSdtHeader};
use td_shim::event_log::{log_hob_list, log_payload_binary, log_payload_parameter};
use td_shim::{
    speculation_barrier, PayloadInfo, TdKernelInfoHobType, TD_ACPI_TABLE_HOB_GUID,
    TD_KERNEL_INFO_HOB_GUID,
};
use td_uefi_pi::{fv, hob, pi};

use crate::ipl::ExecutablePayloadType;
use crate::shim_info::{BootTimeDynamic, BootTimeStatic};

mod acpi;
mod asm;
mod e820;
mod heap;
mod ipl;
mod linux;
mod memory;
mod mp;
mod payload_hob;
mod shim_info;
mod td;

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
// #[cfg(not(test))]
#[no_mangle]
#[cfg_attr(target_os = "uefi", export_name = "efi_main")]
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

    // Initialize the static information from the metadata
    let static_info = BootTimeStatic::new().expect("Invalid metadata");

    // Read additional information from TD HOB if it exists, otherwise convert the metadata
    // sections into memory descriptor.
    let mut dynamic_info =
        BootTimeDynamic::new(&static_info).expect("Fail to initialize dynamic information");

    // Initialize memory subsystem.
    let mut mem = memory::Memory::new(&dynamic_info.memory)
        .expect("Unable to find a piece of suitable memory for runtime");
    mem.setup_paging();

    // Relocate the page table that map all the physical memory
    td::relocate_ap_page_table(mem.layout.runtime_page_table_base);

    // Set up the TD event log buffer.
    // Safe because it's used to initialize the EventLog subsystem which ensures safety.
    let event_log_buf = unsafe {
        memslice::get_dynamic_mem_slice_mut(
            memslice::SliceType::EventLog,
            mem.layout.runtime_event_log_base as usize,
        )
    };
    let mut td_event_log = CcEventLogWriter::new(event_log_buf, Box::new(td::extend_rtmr))
        .expect("Failed to create and initialize the event log");

    // Log the TD HOB if td-shim consumed its content
    if let Some(td_hob) = dynamic_info.td_hob() {
        log_hob_list(td_hob, &mut td_event_log);
    }

    let num_vcpus = td::get_num_vcpus();
    //Create MADT and TDEL
    let (madt, tdel) = prepare_acpi_tables(&mut dynamic_info.acpi_tables, &mem.layout, num_vcpus);
    dynamic_info.acpi_tables.push(madt.as_bytes());
    dynamic_info.acpi_tables.push(tdel.as_bytes());

    // If the Payload Information GUID HOB is present, try to boot the Linux kernel.
    if let Some(payload_info) = dynamic_info.payload_info {
        boot_linux_kernel(
            &payload_info,
            &dynamic_info.acpi_tables,
            &mem,
            &mut td_event_log,
            num_vcpus,
        );
    }

    boot_builtin_payload(&mut mem, &mut td_event_log, &dynamic_info.acpi_tables);

    panic!("payload entry() should not return here, deadloop!!!");
}

fn boot_linux_kernel(
    kernel_info: &PayloadInfo,
    acpi_tables: &Vec<&[u8]>,
    mem: &memory::Memory,
    event_log: &mut CcEventLogWriter,
    vcpus: u32,
) {
    // Create an EV_SEPARATOR event to mark the end of the td-shim events
    event_log.create_seperator();

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
    let payload = unsafe { memslice::get_mem_slice_mut(memslice::SliceType::Kernel) };
    let payload_parameter =
        unsafe { memslice::get_mem_slice(memslice::SliceType::KernelParameter) };

    // Record the payload binary/paramater into event log.
    log_payload_binary(payload, event_log);
    log_payload_parameter(payload_parameter, event_log);

    linux::boot::boot_kernel(
        payload,
        rsdp,
        e820_table.as_slice(),
        mem.layout.runtime_mailbox_base,
        mem.layout.runtime_idt_base,
        kernel_info,
        #[cfg(feature = "tdx")]
        mem.build_unaccepted_memory_bitmap(),
    );
    panic!("Linux kernel should not return here!!!");
}

fn boot_builtin_payload(
    mem: &mut memory::Memory,
    event_log: &mut CcEventLogWriter,
    acpi_tables: &Vec<&[u8]>,
) {
    // Get and parse image file from the payload firmware volume.
    let fv_buffer = memslice::get_mem_slice(memslice::SliceType::ShimPayload);
    let mut payload_bin = fv::get_image_from_fv(
        fv_buffer,
        pi::fv::FV_FILETYPE_DXE_CORE,
        pi::fv::SECTION_PE32,
    )
    .expect("Failed to get image file from Firmware Volume");

    #[cfg(feature = "secure-boot")]
    {
        payload_bin = secure_boot_verify_payload(payload_bin, event_log);
    }

    // Record the payload binary information into event log.
    log_payload_binary(payload_bin, event_log);

    // Create an EV_SEPARATOR event to mark the end of the td-shim events
    event_log.create_seperator();

    // Safe because we are the only user in single-thread context.
    let payload = unsafe {
        memslice::get_dynamic_mem_slice_mut(
            memslice::SliceType::Payload,
            mem.layout.runtime_payload_base as usize,
        )
    };
    let relocation_info = ipl::find_and_report_entry_point(mem, payload_bin, payload)
        .expect("Entry point not found!");

    // Set up NX (no-execute) protection for payload hob
    mem.set_nx_bit(mem.layout.runtime_acpi_base, TD_PAYLOAD_ACPI_SIZE as u64);

    // Prepare the HOB list to run the image
    payload_hob::build_payload_hob(acpi_tables, &mem).expect("Fail to create payload HOB");

    // Finally let's switch stack and jump to the image entry point...
    log::info!(
        " start launching payload {:p}...\n",
        relocation_info.entry_point as *const usize,
    );

    // Relocate the Interrupt Descriptor Table before jump to payload
    switch_idt(mem.layout.runtime_idt_base);

    // Relocate Mailbox along side with the AP function
    td::relocate_mailbox(mem.layout.runtime_mailbox_base as u32);

    match relocation_info.image_type {
        ExecutablePayloadType::Elf => {
            let entry = unsafe {
                core::mem::transmute::<u64, extern "sysv64" fn(u64, u64)>(
                    relocation_info.entry_point,
                )
            };
            entry(
                mem.layout.runtime_acpi_base,
                mem.layout.runtime_payload_base,
            );
        }
        ExecutablePayloadType::PeCoff => {
            let entry = unsafe {
                core::mem::transmute::<u64, extern "win64" fn(u64, u64)>(
                    relocation_info.entry_point,
                )
            };
            entry(
                mem.layout.runtime_acpi_base,
                mem.layout.runtime_payload_base,
            );
        }
    };
}

// We reserved two pages for the IDT used before payload setup
// its own one.
pub fn switch_idt(idt_base: u64) {
    let idt_page = unsafe {
        memslice::get_dynamic_mem_slice_mut(memslice::SliceType::RelocatedIdt, idt_base as usize)
    };

    let mut idt = unsafe { &mut *(idt_page.as_ptr() as u64 as *mut Idt) };

    let handler_offset = size_of::<Idt>();
    let handler_size = empty_exception_handler_size();

    // Copy the handler code into the reserved page
    idt_page[handler_offset..handler_offset + handler_size].copy_from_slice(unsafe {
        core::slice::from_raw_parts(empty_exception_handler as u64 as *const u8, handler_size)
    });

    for entry in &mut idt.entries {
        entry.set_func(idt_base as usize + handler_offset);
    }

    let idt_ptr = idt.idtr();
    unsafe { load_idtr(&idt_ptr) };

    // Set the IDT for application processors
    td::set_idt(&idt_ptr);
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
    let mut acpi = acpi::AcpiTables::new(acpi_slice);

    for &table in acpi_tables {
        acpi.install(table).expect("Failed to install ACPI table");
    }

    acpi.finish().expect("Failed to create XSDT/RSDP")
}

// Prepare ACPI tables for payload and panic if error happens
fn prepare_acpi_tables(
    acpi_tables: &mut Vec<&[u8]>,
    layout: &RuntimeMemoryLayout,
    vcpus: u32,
) -> (Sdt, Ccel) {
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

    let tdel = Ccel::new(
        CCEL_CC_TYPE_TDX,
        0,
        TD_PAYLOAD_EVENT_LOG_SIZE as u64,
        layout.runtime_event_log_base as u64,
    );

    (madt, tdel)
}

#[cfg(feature = "secure-boot")]
fn secure_boot_verify_payload<'a>(
    payload: &'a [u8],
    cc_event_log: &mut CcEventLogWriter,
) -> &'a [u8] {
    use td_shim::event_log::{
        create_event_log_platform_config, PLATFORM_CONFIG_SECURE_AUTHORITY,
        PLATFORM_CONFIG_SECURE_POLICY_DB, PLATFORM_CONFIG_SVN, PLATFORM_FIRMWARE_BLOB2_PAYLOAD,
    };
    use td_shim::secure_boot::PayloadVerifier;

    let cfv = memslice::get_mem_slice(memslice::SliceType::Config);
    let verifier = PayloadVerifier::new(payload, cfv)
        .expect("Secure Boot: Cannot read verify header from payload binary");
    let trust_anchor =
        PayloadVerifier::get_trust_anchor(cfv).expect("Fail to get trust anchor from CFV");

    // Record the provisioned trust anchor into event log.
    create_event_log_platform_config(
        cc_event_log,
        1,
        PLATFORM_CONFIG_SECURE_POLICY_DB,
        trust_anchor,
    )
    .expect("Fail to measure and log the provisioned trust anchor");

    verifier.verify().expect("Verification fails");

    // Record the matched trust anchor which is same as the provisioned
    // trust anchor if it passes the verification.
    create_event_log_platform_config(
        cc_event_log,
        1,
        PLATFORM_CONFIG_SECURE_AUTHORITY,
        trust_anchor,
    )
    .expect("Fail to measure and log the provisioned trust anchor");

    // Record the payload SVN into event log.
    create_event_log_platform_config(
        cc_event_log,
        2,
        PLATFORM_CONFIG_SVN,
        &u64::to_le_bytes(verifier.get_payload_svn()),
    )
    .expect("Fail to measure and log the payload SVN");

    // Parse out the image from signed payload
    return PayloadVerifier::get_payload_image(payload)
        .expect("Unable to get payload image from signed binary");
}
