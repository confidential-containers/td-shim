// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![allow(unused)]
use core::mem::size_of;
use r_efi::efi::Guid;
use std::vec::Vec;
use td_uefi_pi::{fv, hob, pi};

const EFI_END_OF_HOB_LIST_OFFSET: usize = 48;

const HOB_ACPI_TABLE_GUID: [u8; 16] = [
    0x70, 0x58, 0x0c, 0x6a, 0xed, 0xd4, 0xf4, 0x44, 0xa1, 0x35, 0xdd, 0x23, 0x8b, 0x6f, 0xc, 0x8d,
];

const HOB_KERNEL_INFO_GUID: [u8; 16] = [
    0x12, 0xa4, 0x6f, 0xb9, 0x1f, 0x46, 0xe3, 0x4b, 0x8c, 0xd, 0xad, 0x80, 0x5a, 0x49, 0x7a, 0xc0,
];

/// GUID for secure boot trust anchor in the Configuration Firmware Volume (CFV).
const CFV_FFS_HEADER_TRUST_ANCHOR_GUID: Guid = Guid::from_fields(
    0x77a2742e,
    0x9340,
    0x4ac9,
    0x8f,
    0x85,
    &[0xb7, 0xb9, 0x78, 0x58, 0x0, 0x21],
); // {77A2742E-9340-4AC9-8F85-B7B978580021}

pub fn fuzz_hob_parser(buffer: &[u8]) {
    let mut test_buffer = buffer.to_vec();

    // Update ptr in buffer
    let ptr = test_buffer.as_ptr() as u64;
    if test_buffer.len() >= size_of::<pi::hob::HandoffInfoTable>() {
        test_buffer[EFI_END_OF_HOB_LIST_OFFSET..size_of::<pi::hob::HandoffInfoTable>()]
            .copy_from_slice(&u64::to_le_bytes(ptr + buffer.len() as u64)[..]);
    }

    let hob_list = hob::check_hob_integrity(&test_buffer);

    if hob_list.is_some() {
        hob::dump_hob(hob_list.unwrap());
        hob::get_system_memory_size_below_4gb(hob_list.unwrap());
        hob::get_total_memory_top(hob_list.unwrap());
        hob::get_fv(hob_list.unwrap());
        hob::get_next_extension_guid_hob(hob_list.unwrap(), &HOB_ACPI_TABLE_GUID);
        hob::get_next_extension_guid_hob(hob_list.unwrap(), &HOB_KERNEL_INFO_GUID);
        hob::get_guid_data(hob_list.unwrap());
        hob::seek_to_next_hob(hob_list.unwrap());
    }
}

pub fn fuzz_payload_parser(data: &[u8]) {
    let res = fv::get_image_from_fv(data, pi::fv::FV_FILETYPE_DXE_CORE, pi::fv::SECTION_PE32);
}

pub fn fuzz_cfv_parser(data: &[u8]) {
    let res = fv::get_file_from_fv(
        data,
        pi::fv::FV_FILETYPE_RAW,
        CFV_FFS_HEADER_TRUST_ANCHOR_GUID,
    );
}
