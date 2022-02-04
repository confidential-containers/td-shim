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

mod acpi;
#[cfg(feature = "cet-ss")]
mod cet_ss;
mod e820;
mod heap;
mod ipl;
mod linux;
mod memory;
mod mp;
mod stack_guard;
mod tcg;
mod verify;

extern "win64" {
    fn switch_stack_call(entry_point: usize, stack_top: usize, P1: usize, P2: usize);
}

mod asm;

use r_efi::efi;

use tdx_tdcall::tdx;
use uefi_pi::{fv, hob, pi};

use td_layout::build_time::{self, *};
use td_layout::memslice;
use td_layout::runtime::{self, *};
use td_layout::RuntimeMemoryLayout;

use core::panic::PanicInfo;

use core::ffi::c_void;

use crate::e820::create_e820_entries;
use crate::memory::Memory;
use crate::verify::PayloadVerifier;
use scroll::{Pread, Pwrite};
use zerocopy::{AsBytes, FromBytes};

#[repr(C)]
#[derive(Copy, Clone, Debug, Pwrite, Pread)]
pub struct HobTemplate {
    pub handoff_info_table: pi::hob::HandoffInfoTable,
    pub firmware_volume: pi::hob::FirmwareVolume,
    pub cpu: pi::hob::Cpu,
    pub payload: pi::hob::MemoryAllocation,
    pub page_table: pi::hob::MemoryAllocation,
    pub stack: pi::hob::MemoryAllocation,
    pub memory_above_1m: pi::hob::ResourceDescription,
    pub memory_blow_1m: pi::hob::ResourceDescription,
    pub end_off_hob: pi::hob::Header,
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

#[derive(Pread, Pwrite)]
struct Guid {
    data1: u32,
    data2: u32,
    data3: u32,
    data4: u32,
}

const TD_HOB_GUID: Guid = Guid {
    data1: 0xf706dd8f,
    data2: 0x11e9eebe,
    data3: 0xa7e41499,
    data4: 0x51e6daa0,
};

const EV_EFI_EVENT_BASE: u32 = 0x80000000;
const EV_EFI_HANDOFF_TABLES2: u32 = EV_EFI_EVENT_BASE + 0xB;
const EV_PLATFORM_CONFIG_FLAGS: u32 = 0x0000000A;

#[derive(Pwrite)]
struct ConfigurationTable {
    guid: Guid,
    table: u64, // should be usize, usize can't be derived by pwrite, but tdx only support 64bit
}

#[derive(Pwrite)]
struct TdxHandoffTablePointers {
    table_descripion_size: u8,
    table_description: [u8; 8],
    number_of_tables: u64,
    table_entry: [ConfigurationTable; 1],
}

fn log_hob_list(hob_list: &[u8], td_event_log: &mut tcg::TdEventLog) {
    hob::dump_hob(hob_list);

    let hand_off_table_pointers = TdxHandoffTablePointers {
        table_descripion_size: 8,
        table_description: [b't', b'd', b'_', b'h', b'o', b'b', 0, 0],
        number_of_tables: 1,
        table_entry: [ConfigurationTable {
            guid: TD_HOB_GUID,
            table: hob_list as *const _ as *const c_void as u64,
        }],
    };

    let mut tdx_handofftable_pointers_buffer =
        [0u8; core::mem::size_of::<TdxHandoffTablePointers>()];
    let _writen = tdx_handofftable_pointers_buffer
        .pwrite(hand_off_table_pointers, 0)
        .unwrap();

    td_event_log.create_td_event(
        1,
        EV_EFI_HANDOFF_TABLES2,
        &tdx_handofftable_pointers_buffer,
        hob_list,
    );
}

#[derive(Default, Clone, Copy, Pread, Pwrite)]
pub struct PayloadInfo {
    pub image_type: u32,
    pub entry_point: u64,
}

const HOB_ACPI_TABLE_GUID: [u8; 16] = [
    0x70, 0x58, 0x0c, 0x6a, 0xed, 0xd4, 0xf4, 0x44, 0xa1, 0x35, 0xdd, 0x23, 0x8b, 0x6f, 0xc, 0x8d,
];

const HOB_KERNEL_INFO_GUID: [u8; 16] = [
    0x12, 0xa4, 0x6f, 0xb9, 0x1f, 0x46, 0xe3, 0x4b, 0x8c, 0xd, 0xad, 0x80, 0x5a, 0x49, 0x7a, 0xc0,
];

#[cfg(not(test))]
#[no_mangle]
#[export_name = "efi_main"]
pub extern "win64" fn _start(
    boot_fv: *const c_void,
    top_of_stack: *const c_void,
    init_vp: *const c_void,
    info: usize,
) -> ! {
    let _ = td_logger::init();
    log::info!("Starting RUST Based TdShim boot_fv - {:p}, Top of stack - {:p}, init_vp - {:p}, info - 0x{:x} \n", boot_fv, top_of_stack, init_vp, info);
    td_exception::setup_exception_handlers();
    log::info!("setup_exception_handlers done\n");

    //Init temp heap
    heap::init();

    let hob_list = memslice::get_mem_slice(memslice::SliceType::ShimHob);
    let hob_size = hob::get_hob_total_size(hob_list).unwrap();
    let hob_list = &hob_list[0..hob_size];
    hob::dump_hob(hob_list);
    let mut td_info = tdx::TdInfoReturnData {
        gpaw: 0,
        attributes: 0,
        max_vcpus: 0,
        num_vcpus: 0,
        rsvd: [0; 3],
    };
    tdx::tdcall_get_td_info(&mut td_info);

    log::info!("gpaw - {:?}\n", td_info.gpaw);
    log::info!("num_vcpus - {:?}\n", td_info.num_vcpus);

    let memory_top = hob::get_system_memory_size_below_4gb(hob_list).unwrap();
    let runtime_memory_layout = RuntimeMemoryLayout::new(memory_top);

    let mut e820_table = e820::E820Table::new();

    // Read the system memory information from TD HOB, accept system memory and
    // add them into the e820 table together with memory reserved by VMM.
    let mut offset: usize = 0;
    loop {
        let hob = &hob_list[offset..];
        let header: pi::hob::Header = hob.pread(0).unwrap();
        match header.r#type {
            pi::hob::HOB_TYPE_RESOURCE_DESCRIPTOR => {
                let resource_hob: pi::hob::ResourceDescription = hob.pread(0).unwrap();
                match resource_hob.resource_type {
                    pi::hob::RESOURCE_SYSTEM_MEMORY => {
                        mp::mp_accept_memory_resource_range(
                            td_info.num_vcpus,
                            resource_hob.physical_start,
                            resource_hob.resource_length,
                        );
                    }
                    pi::hob::RESOURCE_MEMORY_RESERVED => {}
                    _ => {}
                }
            }
            pi::hob::HOB_TYPE_END_OF_HOB_LIST => {
                break;
            }
            _ => {}
        }
        offset = hob::align_to_next_hob_offset(hob_list.len(), offset, header.length).unwrap();
    }

    let memory_bottom = runtime_memory_layout.runtime_memory_bottom;

    let td_payload_hob_base = runtime_memory_layout.runtime_hob_base;
    let td_payload_stack_base = runtime_memory_layout.runtime_stack_base;
    let td_payload_shadow_stack_base = runtime_memory_layout.runtime_shadow_stack_base;
    let td_payload_shadow_stack_top = runtime_memory_layout.runtime_shadow_stack_top;
    let td_event_log_base = runtime_memory_layout.runtime_event_log_base;
    let td_acpi_base = runtime_memory_layout.runtime_acpi_base;

    td_paging::init();

    // Safe because it's used to initialize the EventLog subsystem which ensures safety.
    let event_log_buf = unsafe {
        memslice::get_dynamic_mem_slice_mut(
            memslice::SliceType::EventLog,
            td_event_log_base as usize,
        )
    };
    let mut td_event_log = tcg::TdEventLog::init(event_log_buf);
    log_hob_list(hob_list, &mut td_event_log);

    let fv_buffer = memslice::get_mem_slice(memslice::SliceType::ShimPayload);
    let _hob_buffer = memslice::get_mem_slice(memslice::SliceType::ShimHob);

    let _hob_header = pi::hob::Header {
        r#type: pi::hob::HOB_TYPE_END_OF_HOB_LIST,
        length: core::mem::size_of::<pi::hob::Header>() as u16,
        reserved: 0,
    };

    let handoff_info_table = pi::hob::HandoffInfoTable {
        header: pi::hob::Header {
            r#type: pi::hob::HOB_TYPE_HANDOFF,
            length: core::mem::size_of::<pi::hob::HandoffInfoTable>() as u16,
            reserved: 0,
        },
        version: 9u32,
        boot_mode: pi::boot_mode::BOOT_WITH_FULL_CONFIGURATION,
        efi_memory_top: memory_top,
        efi_memory_bottom: memory_bottom,
        efi_free_memory_top: memory_top,
        efi_free_memory_bottom: memory_bottom
            + ipl::efi_page_to_size(ipl::efi_size_to_page(
                core::mem::size_of::<HobTemplate>() as u64
            )),
        efi_end_of_hob_list: td_payload_hob_base + core::mem::size_of::<HobTemplate>() as u64,
    };

    let cpu = pi::hob::Cpu {
        header: pi::hob::Header {
            r#type: pi::hob::HOB_TYPE_CPU,
            length: core::mem::size_of::<pi::hob::Cpu>() as u16,
            reserved: 0,
        },
        size_of_memory_space: ipl::cpu_get_memory_space_size(),
        size_of_io_space: 16u8,
        reserved: [0u8; 6],
    };

    let firmware_volume = pi::hob::FirmwareVolume {
        header: pi::hob::Header {
            r#type: pi::hob::HOB_TYPE_FV,
            length: core::mem::size_of::<pi::hob::FirmwareVolume>() as u16,
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
            length: core::mem::size_of::<pi::hob::MemoryAllocation>() as u16,
            reserved: 0,
        },
        alloc_descriptor: pi::hob::MemoryAllocationHeader {
            name: *MEMORY_ALLOCATION_STACK_GUID.as_bytes(),
            memory_base_address: td_payload_stack_base as u64,
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

    let memory_size = ipl::get_memory_size(hob_list);
    let mut mem = Memory::new(&runtime_memory_layout, memory_size);

    mem.setup_paging();

    if let Some(hob) = hob::get_next_extension_guid_hob(hob_list, &HOB_KERNEL_INFO_GUID) {
        let kernel_info = hob::get_guid_data(hob).unwrap();
        let vmm_kernel = kernel_info.pread::<PayloadInfo>(0).unwrap();

        match vmm_kernel.image_type {
            0 => {}
            1 => {
                // Safe because we are the only consumer.
                let acpi_slice = unsafe {
                    memslice::get_dynamic_mem_slice_mut(
                        memslice::SliceType::Acpi,
                        td_acpi_base as usize,
                    )
                };
                let mut acpi_tables = acpi::AcpiTables::new(acpi_slice);

                //Create and install MADT and TDEL
                let madt = mp::create_madt(
                    td_info.num_vcpus as u8,
                    build_time::TD_SHIM_MAILBOX_BASE as u64,
                );
                let tdel = td_event_log.create_tdel();
                acpi_tables.install(&madt.data);
                acpi_tables.install(tdel.as_bytes());

                let mut next_hob = hob_list;
                while let Some(hob) =
                    hob::get_next_extension_guid_hob(next_hob, &HOB_ACPI_TABLE_GUID)
                {
                    acpi_tables.install(hob::get_guid_data(hob).unwrap());
                    next_hob = hob::seek_to_next_hob(hob).unwrap();
                }

                // When all the ACPI tables are put into the ACPI memory
                // build the XSDT and RSDP
                let rsdp = acpi_tables.finish();
                let e820_table = create_e820_entries(&runtime_memory_layout);
                // Safe because we are handle off this buffer to linux kernel.
                let payload = unsafe { memslice::get_mem_slice_mut(memslice::SliceType::Payload) };

                linux::boot::boot_kernel(payload, rsdp, e820_table.as_slice());
                panic!("deadloop");
            }
            _ => {
                panic!("deadloop");
            }
        }
    }

    let page_table = pi::hob::MemoryAllocation {
        header: pi::hob::Header {
            r#type: pi::hob::HOB_TYPE_MEMORY_ALLOCATION,
            length: core::mem::size_of::<pi::hob::MemoryAllocation>() as u16,
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
            length: core::mem::size_of::<pi::hob::ResourceDescription>() as u16,
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
            length: core::mem::size_of::<pi::hob::ResourceDescription>() as u16,
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

    let mut payload = fv::get_image_from_fv(
        fv_buffer,
        pi::fv::FV_FILETYPE_DXE_CORE,
        pi::fv::SECTION_PE32,
    )
    .unwrap();

    #[cfg(feature = "secure-boot")]
    {
        let cfv = memslice::get_mem_slice(memslice::SliceType::Config);
        let verifier = PayloadVerifier::new(payload, cfv);
        if let Some(verifier) = &verifier {
            td_event_log.create_td_event(
                4,
                EV_PLATFORM_CONFIG_FLAGS,
                b"td payload",
                PayloadVerifier::get_trust_anchor(cfv),
            );
            verifier.verify().expect("Verification fails");
            td_event_log.create_td_event(4, EV_PLATFORM_CONFIG_FLAGS, b"td payload", payload);
            td_event_log.create_td_event(
                4,
                EV_PLATFORM_CONFIG_FLAGS,
                b"td payload svn",
                &u64::to_le_bytes(verifier.get_payload_svn()),
            );
            // Parse out the image from signed payload
            payload = PayloadVerifier::get_payload_image(payload);
        } else {
            panic!("Secure Boot: Cannot read verify header from payload binary");
        }
    }

    let (entry, basefw, basefwsize) =
        ipl::find_and_report_entry_point(&mut mem, payload).expect("Entry point not found!");
    let entry = entry as usize;

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
            length: core::mem::size_of::<pi::hob::MemoryAllocation>() as u16,
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
            length: core::mem::size_of::<pi::hob::Header>() as u16,
            reserved: 0,
        },
    };

    // Safe because we are the only consumer.
    let hob_slice = unsafe {
        memslice::get_dynamic_mem_slice_mut(
            memslice::SliceType::PayloadHob,
            td_payload_hob_base as usize,
        )
    };
    let _res = hob_slice.pwrite(hob_template, 0);

    stack_guard::stack_guard_enable(&mut mem);

    #[cfg(feature = "cet-ss")]
    cet_ss::enable_cet_ss(td_payload_shadow_stack_base, td_payload_shadow_stack_top);

    let stack_top = (td_payload_stack_base + TD_PAYLOAD_STACK_SIZE as u64) as usize;
    log::info!(
        " start launching payload {:p} and switch stack {:p}...\n",
        entry as *const usize,
        stack_top as *const usize
    );

    unsafe {
        switch_stack_call(entry, stack_top, td_payload_hob_base as usize, 0);
    }

    panic!("deadloop");
}
