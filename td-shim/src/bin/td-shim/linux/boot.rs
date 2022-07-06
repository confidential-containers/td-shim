// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::mem::size_of;
use scroll::{Pread, Pwrite};
use td_layout as layout;
use td_layout::runtime::{TD_PAYLOAD_PARAM_BASE, TD_PAYLOAD_PARAM_SIZE};
use td_shim::{e820::E820Entry, PayloadInfo, TdKernelInfoHobType};
use x86_64::{
    instructions::{segmentation::Segment, tables::lgdt},
    registers::segmentation as seg,
    structures::{gdt, DescriptorTablePointer},
    PrivilegeLevel as RPL, VirtAddr,
};

use crate::linux::kernel_param::{BootParams, SetupHeader};

const KERNEL_64BIT_ENTRY_OFFSET: u64 = 0x200;
const GDT: [u64; 4] = [
    0,
    0,
    gdt::DescriptorFlags::KERNEL_CODE64.bits(),
    gdt::DescriptorFlags::KERNEL_DATA.bits(),
];

pub enum Error {
    InvalidBzImage,
    UnknownImageType,
}

pub fn setup_header(kernel_image: &[u8]) -> Result<SetupHeader, Error> {
    let mut setup_header = SetupHeader::from_file(kernel_image);

    if setup_header.header != 0x5372_6448 {
        return Err(Error::InvalidBzImage);
    }

    if (setup_header.version < 0x0200) || ((setup_header.loadflags & 0x1) == 0x0) {
        return Err(Error::InvalidBzImage);
    }

    let setup_sects = match setup_header.setup_sects {
        0 => 4,
        n => n as u32,
    };

    let setup_bytes = (setup_sects + 1) * 512;

    setup_header.type_of_loader = 0xff;
    setup_header.code32_start = kernel_image.as_ptr() as u32 + setup_bytes;
    setup_header.cmd_line_ptr = TD_PAYLOAD_PARAM_BASE as u32;

    Ok(setup_header)
}

pub fn boot_kernel(
    kernel: &[u8],
    rsdp_addr: u64,
    e820: &[E820Entry],
    info: &PayloadInfo,
    #[cfg(feature = "tdx")] unaccepted_bitmap: u64,
) -> Result<(), Error> {
    let mut params: BootParams = BootParams::default();
    params.acpi_rsdp_addr = rsdp_addr;
    params.e820_entries = e820.len() as u8;
    params.e820_table[..e820.len()].copy_from_slice(e820);
    #[cfg(feature = "tdx")]
    {
        params.unaccepted_memory = unaccepted_bitmap;
    }

    let image_type = TdKernelInfoHobType::from(info.image_type);
    let entry64 = match image_type {
        TdKernelInfoHobType::BzImage => {
            params.hdr = setup_header(kernel)?;
            params.hdr.code32_start as u64 + 0x200
        }
        TdKernelInfoHobType::RawVmLinux => {
            params.hdr.type_of_loader = 0xff;
            params.hdr.boot_flag = 0xaa55;
            params.hdr.header = 0x5372_6448;
            params.hdr.kernel_alignment = 0x0100_0000;
            params.hdr.cmd_line_ptr = TD_PAYLOAD_PARAM_BASE as u32;
            params.hdr.cmdline_size = TD_PAYLOAD_PARAM_SIZE as u32;
            info.entry_point
        }
        _ => return Err(Error::UnknownImageType),
    };

    // Set the GDT, CS/DS/ES/SS, and disable interrupt
    let gdtr = DescriptorTablePointer {
        limit: (size_of::<u64>() * 4) as u16,
        base: VirtAddr::new(GDT.as_ptr() as u64),
    };

    unsafe {
        lgdt(&gdtr);
        seg::CS::set_reg(seg::SegmentSelector::new(2, RPL::Ring0));
        seg::DS::set_reg(seg::SegmentSelector::new(3, RPL::Ring0));
        seg::ES::set_reg(seg::SegmentSelector::new(3, RPL::Ring0));
        seg::SS::set_reg(seg::SegmentSelector::new(3, RPL::Ring0));
        x86_64::instructions::interrupts::disable();
    }

    // Jump to kernel 64-bit entrypoint
    log::info!("Jump to kernel...\n");

    // Calling kernel 64bit entry follows sysv64 calling convention
    let entry64: extern "sysv64" fn(usize, usize) = unsafe { core::mem::transmute(entry64) };
    entry64(0, &params as *const _ as usize);

    Ok(())
}
