// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

use core::mem::size_of;
use std::env;
use std::fs;
use std::fs::File;
use std::io::Write;

use pe_loader::pe;

use r_efi::efi::Guid;
use r_uefi_pi::fv::*;
use td_layout::build_time::*;
use td_layout::mailbox::*;
use td_layout::metadata::*;

#[cfg(feature = "boot-kernel")]
use td_layout::runtime::{
    TD_PAYLOAD_BASE, TD_PAYLOAD_PARAM_BASE, TD_PAYLOAD_PARAM_SIZE, TD_PAYLOAD_SIZE,
};

use scroll::{Pread, Pwrite};

const RELOCATE_PAYLOAD: u8 = 0;

#[repr(C)]
#[derive(Copy, Clone, Debug, Pwrite, Default)]
struct PayloadFvHeader {
    fv_header: FirmwareVolumeHeader,
    fv_block_map: [FvBlockMap; 2],
    pad_ffs_header: FfsFileHeader,
    fv_ext_header: FirmwareVolumeExtHeader,
    pad: [u8; 4],
}

#[derive(Copy, Clone, Debug, Pread, Pwrite, Default)]
struct PayloadFvFfsHeader {
    ffs_header: FfsFileHeader,
}

#[derive(Copy, Clone, Debug, Pread, Pwrite, Default)]
struct PayloadFvFfsSectionHeader {
    section_header: CommonSectionHeader,
}

#[repr(C, align(4))]
struct PayloadFvHeaderByte {
    data: [u8; size_of::<PayloadFvHeader>()
        + size_of::<PayloadFvFfsHeader>()
        + size_of::<PayloadFvFfsSectionHeader>()],
}

fn write_u24(data: u32, buf: &mut [u8]) {
    assert_eq!(data < 0xffffff, true);
    buf[0] = (data & 0xFF) as u8;
    buf[1] = ((data >> 8) & 0xFF) as u8;
    buf[2] = ((data >> 16) & 0xFF) as u8;
}

fn build_tdx_payload_fv_header(payload_fv_header: &mut [u8]) {
    let mut tdx_payload_fv_header = PayloadFvHeader::default();

    let fv_header_size = (size_of::<PayloadFvHeader>()) as usize;

    tdx_payload_fv_header.fv_header.zero_vector = [0u8; 16];
    tdx_payload_fv_header
        .fv_header
        .file_system_guid
        .copy_from_slice(FIRMWARE_FILE_SYSTEM2_GUID.as_bytes());
    tdx_payload_fv_header.fv_header.fv_length = TD_SHIM_PAYLOAD_SIZE as u64;
    tdx_payload_fv_header.fv_header.signature = FVH_SIGNATURE;
    tdx_payload_fv_header.fv_header.attributes = 0x0004f6ff;
    tdx_payload_fv_header.fv_header.header_length = 0x0048;
    tdx_payload_fv_header.fv_header.checksum = 0xdc0a;
    tdx_payload_fv_header.fv_header.ext_header_offset = 0x0060;
    tdx_payload_fv_header.fv_header.reserved = 0x00;
    tdx_payload_fv_header.fv_header.revision = 0x02;

    tdx_payload_fv_header.fv_block_map[0].num_blocks = (TD_SHIM_PAYLOAD_SIZE as u32) / 0x1000;
    tdx_payload_fv_header.fv_block_map[0].length = 0x1000;
    tdx_payload_fv_header.fv_block_map[1].num_blocks = 0x0000;
    tdx_payload_fv_header.fv_block_map[1].length = 0x0000;

    tdx_payload_fv_header.pad_ffs_header.name.copy_from_slice(
        Guid::from_fields(
            0x00000000,
            0x0000,
            0x0000,
            0x00,
            0x00,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        )
        .as_bytes(),
    );
    tdx_payload_fv_header.pad_ffs_header.integrity_check = 0xaae4;
    tdx_payload_fv_header.pad_ffs_header.r#type = FV_FILETYPE_FFS_PAD;
    tdx_payload_fv_header.pad_ffs_header.attributes = 0x00;
    write_u24(0x2c, &mut tdx_payload_fv_header.pad_ffs_header.size);
    tdx_payload_fv_header.pad_ffs_header.state = 0x07u8;

    tdx_payload_fv_header.fv_ext_header.fv_name.copy_from_slice(
        Guid::from_fields(
            0x7cb8bdc9,
            0xf8eb,
            0x4f34,
            0xaa,
            0xea,
            &[0x3e, 0xe4, 0xaf, 0x65, 0x16, 0xa1],
        )
        .as_bytes(),
    );
    tdx_payload_fv_header.fv_ext_header.ext_header_size = 0x14;

    tdx_payload_fv_header.pad = [0u8; 4];

    let res1 = payload_fv_header.pwrite(tdx_payload_fv_header, 0).unwrap();
    assert_eq!(res1, 120);

    let mut tdx_payload_fv_ffs_header = PayloadFvFfsHeader::default();
    tdx_payload_fv_ffs_header.ffs_header.name.copy_from_slice(
        Guid::from_fields(
            0xa8f75d7c,
            0x8b85,
            0x49b6,
            0x91,
            0x3e,
            &[0xaf, 0x99, 0x61, 0x55, 0x73, 0x08],
        )
        .as_bytes(),
    );
    tdx_payload_fv_ffs_header.ffs_header.integrity_check = 0xaa4c;
    tdx_payload_fv_ffs_header.ffs_header.r#type = FV_FILETYPE_DXE_CORE;
    tdx_payload_fv_ffs_header.ffs_header.attributes = 0x00;
    write_u24(
        TD_SHIM_PAYLOAD_SIZE - fv_header_size as u32,
        &mut tdx_payload_fv_ffs_header.ffs_header.size,
    );
    tdx_payload_fv_ffs_header.ffs_header.state = 0x07u8;

    let res2 = payload_fv_header
        .pwrite(tdx_payload_fv_ffs_header, fv_header_size)
        .unwrap();
    assert_eq!(res2, 24);

    let mut tdx_payload_fv_ffs_section_header = PayloadFvFfsSectionHeader::default();
    write_u24(
        TD_SHIM_PAYLOAD_SIZE - fv_header_size as u32 - size_of::<FfsFileHeader>() as u32,
        &mut tdx_payload_fv_ffs_section_header.section_header.size,
    );
    tdx_payload_fv_ffs_section_header.section_header.r#type = SECTION_PE32;

    let res3 = payload_fv_header
        .pwrite(
            tdx_payload_fv_ffs_section_header,
            fv_header_size + size_of::<PayloadFvFfsHeader>(),
        )
        .unwrap();
    assert_eq!(res3, 4);
}

type IplFvHeader = PayloadFvHeader;
type IplFvFfsHeader = PayloadFvFfsHeader;
type IplFvFfsSectionHeader = PayloadFvFfsSectionHeader;
type IplFvHeaderByte = PayloadFvHeaderByte;

fn build_tdx_ipl_fv_header(ipl_fv_header: &mut [u8]) {
    let mut tdx_ipl_fv_header = IplFvHeader::default();

    let fv_header_size = (size_of::<PayloadFvHeader>()) as usize;

    tdx_ipl_fv_header.fv_header.zero_vector = [0u8; 16];
    tdx_ipl_fv_header
        .fv_header
        .file_system_guid
        .copy_from_slice(FIRMWARE_FILE_SYSTEM2_GUID.as_bytes());
    tdx_ipl_fv_header.fv_header.fv_length = (TD_SHIM_IPL_SIZE + TD_SHIM_RESET_VECTOR_SIZE) as u64;
    tdx_ipl_fv_header.fv_header.signature = FVH_SIGNATURE;
    tdx_ipl_fv_header.fv_header.attributes = 0x0004f6ff;
    tdx_ipl_fv_header.fv_header.header_length = 0x0048;
    tdx_ipl_fv_header.fv_header.checksum = 0x3d21;
    tdx_ipl_fv_header.fv_header.ext_header_offset = 0x0060;
    tdx_ipl_fv_header.fv_header.reserved = 0x00;
    tdx_ipl_fv_header.fv_header.revision = 0x02;

    tdx_ipl_fv_header.fv_block_map[0].num_blocks =
        (TD_SHIM_IPL_SIZE + TD_SHIM_RESET_VECTOR_SIZE) / 0x1000;
    tdx_ipl_fv_header.fv_block_map[0].length = 0x1000;
    tdx_ipl_fv_header.fv_block_map[1].num_blocks = 0x0000;
    tdx_ipl_fv_header.fv_block_map[1].length = 0x0000;

    tdx_ipl_fv_header.pad_ffs_header.name.copy_from_slice(
        Guid::from_fields(
            0x00000000,
            0x0000,
            0x0000,
            0x00,
            0x00,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        )
        .as_bytes(),
    );
    tdx_ipl_fv_header.pad_ffs_header.integrity_check = 0xaae4;
    tdx_ipl_fv_header.pad_ffs_header.r#type = FV_FILETYPE_FFS_PAD;
    tdx_ipl_fv_header.pad_ffs_header.attributes = 0x00;
    write_u24(0x2c, &mut tdx_ipl_fv_header.pad_ffs_header.size);
    tdx_ipl_fv_header.pad_ffs_header.state = 0x07u8;

    tdx_ipl_fv_header.fv_ext_header.fv_name.copy_from_slice(
        Guid::from_fields(
            0x763bed0d,
            0xde9f,
            0x48f5,
            0x81,
            0xf1,
            &[0x3e, 0x90, 0xe1, 0xb1, 0xa0, 0x15],
        )
        .as_bytes(),
    );

    tdx_ipl_fv_header.fv_ext_header.ext_header_size = 0x14;

    tdx_ipl_fv_header.pad = [0u8; 4];

    let _res = ipl_fv_header.pwrite(tdx_ipl_fv_header, 0).unwrap();

    let mut tdx_ipl_fv_ffs_header = IplFvFfsHeader::default();
    tdx_ipl_fv_ffs_header.ffs_header.name.copy_from_slice(
        Guid::from_fields(
            0x17ed4c9e,
            0x05e0,
            0x48a6,
            0xa0,
            0x1d,
            &[0xfb, 0x0f, 0xa9, 0x1e, 0x63, 0x98],
        )
        .as_bytes(),
    );
    tdx_ipl_fv_ffs_header.ffs_header.integrity_check = 0xaa0d;
    tdx_ipl_fv_ffs_header.ffs_header.r#type = FV_FILETYPE_SECURITY_CORE;
    tdx_ipl_fv_ffs_header.ffs_header.attributes = 0x00;
    write_u24(
        TD_SHIM_IPL_SIZE - fv_header_size as u32,
        &mut tdx_ipl_fv_ffs_header.ffs_header.size,
    );
    tdx_ipl_fv_ffs_header.ffs_header.state = 0x07u8;

    let _res = ipl_fv_header
        .pwrite(tdx_ipl_fv_ffs_header, fv_header_size)
        .unwrap();

    let mut tdx_ipl_fv_ffs_section_header = IplFvFfsSectionHeader::default();
    write_u24(
        TD_SHIM_IPL_SIZE - fv_header_size as u32 - size_of::<FfsFileHeader>() as u32,
        &mut tdx_ipl_fv_ffs_section_header.section_header.size,
    );
    tdx_ipl_fv_ffs_section_header.section_header.r#type = SECTION_PE32;

    let _res = ipl_fv_header
        .pwrite(
            tdx_ipl_fv_ffs_section_header,
            fv_header_size + size_of::<IplFvFfsHeader>(),
        )
        .unwrap();
}

#[repr(C)]
#[derive(Debug, Default, Pwrite)]
struct ResetVectorHeader {
    ffs_header: FfsFileHeader,
    section_header_pad: CommonSectionHeader,
    pad: [u8; 8],
    section_header_reset_vector: CommonSectionHeader,
}

const RESET_VECTOR_HEADER_SIZE: usize = size_of::<ResetVectorHeader>();
#[repr(C, align(4))]
#[derive(Debug, Clone, Copy)]
struct ResetVectorByte {
    data: [u8; RESET_VECTOR_HEADER_SIZE],
}
impl Default for ResetVectorByte {
    fn default() -> Self {
        ResetVectorByte {
            data: [0u8; RESET_VECTOR_HEADER_SIZE],
        }
    }
}

fn build_tdx_reset_vector_header(reset_vector_header: &mut [u8]) {
    let mut tdx_reset_vector_header = ResetVectorHeader::default();

    tdx_reset_vector_header.ffs_header.name.copy_from_slice(
        Guid::from_fields(
            0x1ba0062e,
            0xc779,
            0x4582,
            0x85,
            0x66,
            &[0x33, 0x6a, 0xe8, 0xf7, 0x8f, 0x09],
        )
        .as_bytes(),
    );
    tdx_reset_vector_header.ffs_header.integrity_check = 0xaa5a;
    tdx_reset_vector_header.ffs_header.r#type = FV_FILETYPE_RAW;
    tdx_reset_vector_header.ffs_header.attributes = 0x08;
    write_u24(
        TD_SHIM_RESET_VECTOR_SIZE + size_of::<ResetVectorHeader>() as u32,
        &mut tdx_reset_vector_header.ffs_header.size,
    );
    tdx_reset_vector_header.ffs_header.state = 0x07u8;

    write_u24(0x0c, &mut tdx_reset_vector_header.section_header_pad.size);
    tdx_reset_vector_header.section_header_pad.r#type = SECTION_RAW;

    tdx_reset_vector_header.pad = [0u8; 8];

    write_u24(
        TD_SHIM_RESET_VECTOR_SIZE + size_of::<CommonSectionHeader>() as u32,
        &mut tdx_reset_vector_header.section_header_reset_vector.size,
    );
    tdx_reset_vector_header.section_header_reset_vector.r#type = SECTION_RAW;

    let _res = reset_vector_header
        .pwrite(tdx_reset_vector_header, 0)
        .unwrap();
}

fn build_tdx_metadata_ptr(metadata_ptr: &mut [u8]) {
    let mut tdx_metadata_ptr = TdxMetadataPtr::default();
    tdx_metadata_ptr.ptr = TD_SHIM_METADATA_OFFSET;
    let _res = metadata_ptr.pwrite(tdx_metadata_ptr, 0).unwrap();
}

fn build_tdx_metadata(metadata: &mut [u8]) {
    let mut tdx_metadata = TdxMetadata::default();

    // BFV
    tdx_metadata.sections[0].data_offset = TD_SHIM_PAYLOAD_OFFSET;
    tdx_metadata.sections[0].raw_data_size =
        TD_SHIM_PAYLOAD_SIZE + TD_SHIM_IPL_SIZE + TD_SHIM_RESET_VECTOR_SIZE;
    tdx_metadata.sections[0].memory_address = TD_SHIM_PAYLOAD_BASE as u64;
    tdx_metadata.sections[0].memory_data_size =
        (TD_SHIM_PAYLOAD_SIZE + TD_SHIM_IPL_SIZE + TD_SHIM_RESET_VECTOR_SIZE) as u64;
    tdx_metadata.sections[0].r#type = TDX_METADATA_SECTION_TYPE_BFV;
    tdx_metadata.sections[0].attributes = TDX_METADATA_ATTRIBUTES_EXTENDMR;
    // CFV
    tdx_metadata.sections[1].data_offset = TD_SHIM_CONFIG_OFFSET;
    tdx_metadata.sections[1].raw_data_size = TD_SHIM_CONFIG_SIZE;
    tdx_metadata.sections[1].memory_address = TD_SHIM_CONFIG_BASE as u64;
    tdx_metadata.sections[1].memory_data_size = TD_SHIM_CONFIG_SIZE as u64;
    tdx_metadata.sections[1].r#type = TDX_METADATA_SECTION_TYPE_CFV;
    tdx_metadata.sections[1].attributes = 0;
    // stack
    tdx_metadata.sections[2].data_offset = 0;
    tdx_metadata.sections[2].raw_data_size = 0;
    tdx_metadata.sections[2].memory_address = TD_SHIM_TEMP_STACK_BASE as u64;
    tdx_metadata.sections[2].memory_data_size = TD_SHIM_TEMP_STACK_SIZE as u64;
    tdx_metadata.sections[2].r#type = TDX_METADATA_SECTION_TYPE_TEMP_MEM;
    tdx_metadata.sections[2].attributes = 0;
    // heap
    tdx_metadata.sections[3].data_offset = 0;
    tdx_metadata.sections[3].raw_data_size = 0;
    tdx_metadata.sections[3].memory_address = TD_SHIM_TEMP_HEAP_BASE as u64;
    tdx_metadata.sections[3].memory_data_size = TD_SHIM_TEMP_HEAP_SIZE as u64;
    tdx_metadata.sections[3].r#type = TDX_METADATA_SECTION_TYPE_TEMP_MEM;
    tdx_metadata.sections[3].attributes = 0;
    // TD_HOB
    tdx_metadata.sections[4].data_offset = 0;
    tdx_metadata.sections[4].raw_data_size = 0;
    tdx_metadata.sections[4].memory_address = TD_SHIM_HOB_BASE as u64;
    tdx_metadata.sections[4].memory_data_size = TD_SHIM_HOB_SIZE as u64;
    tdx_metadata.sections[4].r#type = TDX_METADATA_SECTION_TYPE_TD_HOB;
    tdx_metadata.sections[4].attributes = 0;
    // MAILBOX
    tdx_metadata.sections[5].data_offset = 0;
    tdx_metadata.sections[5].raw_data_size = 0;
    tdx_metadata.sections[5].memory_address = TD_SHIM_MAILBOX_BASE as u64;
    tdx_metadata.sections[5].memory_data_size = TD_SHIM_MAILBOX_SIZE as u64;
    tdx_metadata.sections[5].r#type = TDX_METADATA_SECTION_TYPE_TEMP_MEM;
    tdx_metadata.sections[5].attributes = 0;

    #[cfg(feature = "boot-kernel")]
    {
        // kernel image
        tdx_metadata.payload_sections[0].data_offset = 0;
        tdx_metadata.payload_sections[0].raw_data_size = 0;
        tdx_metadata.payload_sections[0].memory_address = TD_PAYLOAD_BASE as u64;
        tdx_metadata.payload_sections[0].memory_data_size = TD_PAYLOAD_SIZE as u64;
        tdx_metadata.payload_sections[0].r#type = TDX_METADATA_SECTION_TYPE_PAYLOAD;
        tdx_metadata.payload_sections[0].attributes = 0;

        //parameters
        tdx_metadata.payload_sections[1].data_offset = 0;
        tdx_metadata.payload_sections[1].raw_data_size = 0;
        tdx_metadata.payload_sections[1].memory_address = TD_PAYLOAD_PARAM_BASE as u64;
        tdx_metadata.payload_sections[1].memory_data_size = TD_PAYLOAD_PARAM_SIZE as u64;
        tdx_metadata.payload_sections[1].r#type = TDX_METADATA_SECTION_TYPE_PAYLOAD_PARAM;
        tdx_metadata.payload_sections[1].attributes = 0;
    }

    let _res = metadata.pwrite(tdx_metadata, 0).unwrap();
}

fn build_tdx_mpwakeup_mailbox(mailbox: &mut [u8]) {
    let mut tdx_mailbox = TdxMpWakeupMailbox::default();

    tdx_mailbox.command = 0;
    tdx_mailbox.rsvd = 0;
    tdx_mailbox.apic_id = 0xffffffff;
    tdx_mailbox.wakeup_vector = 0;

    let writen = mailbox.pwrite(tdx_mailbox, 0).unwrap();
    assert_eq!(writen, 16);
}

fn main() -> std::io::Result<()> {
    use env_logger::Env;
    let env = Env::default()
        .filter_or("MY_LOG_LEVEL", "info")
        .write_style_or("MY_LOG_STYLE", "always");
    env_logger::init_from_env(env);

    let args: Vec<String> = env::args().collect();
    let reset_vector_name = &args[1];
    let rust_ipl_name = &args[2];
    let rust_payload_name = &args[3];
    let rust_firmware_name = &args[4];

    println!(
        "\nrust-td-tool {} {} {} {}\n",
        reset_vector_name, rust_ipl_name, rust_payload_name, rust_firmware_name
    );

    let reset_vector_bin = fs::read(reset_vector_name).expect("fail to read reset_vector");
    //println!("{:?}", reset_vector_bin);
    let rust_ipl_bin = fs::read(rust_ipl_name).expect("fail to read rust IPL");
    let rust_payload_bin = fs::read(rust_payload_name).expect("fail to read rust payload");

    let mut rust_firmware_file =
        File::create(rust_firmware_name).expect("fail to create rust firmware");

    let aug_buf = vec![0x00u8; TD_SHIM_PAYLOAD_OFFSET as usize];
    let zero_buf = vec![0x00u8; TD_SHIM_FIRMWARE_SIZE as usize];

    let mut mailbox = [0u8; size_of::<TdxMpWakeupMailbox>()];
    build_tdx_mpwakeup_mailbox(&mut mailbox);

    let mut rust_payload_header_byte = PayloadFvHeaderByte {
        data: [0u8; size_of::<PayloadFvHeaderByte>()],
    };
    let rust_payload_header = &mut rust_payload_header_byte.data;
    build_tdx_payload_fv_header(rust_payload_header);

    let mut metadata = [0u8; size_of::<TdxMetadata>()];
    build_tdx_metadata(&mut metadata);

    let mut rust_ipl_header_byte = IplFvHeaderByte {
        data: [0u8; size_of::<IplFvHeaderByte>()],
    };
    let rust_ipl_header = &mut rust_ipl_header_byte.data;
    build_tdx_ipl_fv_header(rust_ipl_header);

    let mut reset_vector_header_byte = ResetVectorByte {
        data: [0u8; size_of::<ResetVectorByte>()],
    };
    let reset_vector_header = &mut reset_vector_header_byte.data;
    build_tdx_reset_vector_header(reset_vector_header);

    let mut metadata_ptr = [0u8; size_of::<TdxMetadataPtr>()];
    build_tdx_metadata_ptr(&mut metadata_ptr);

    let mut new_rust_payload_buf =
        vec![0x00u8; TD_SHIM_PAYLOAD_SIZE as usize - rust_payload_header.len() - metadata.len()];
    if RELOCATE_PAYLOAD != 0 {
        let reloc = pe::relocate(
            &rust_payload_bin[..],
            &mut new_rust_payload_buf[..],
            TD_SHIM_PAYLOAD_BASE as usize + rust_payload_header.len(),
        );
        match reloc {
            Some(entry_point) => println!("reloc payload entrypoint - 0x{:x}", entry_point),
            None => println!("reloc payload fail"),
        }
    }

    let mut new_rust_ipl_buf =
        vec![0x00u8; TD_SHIM_IPL_SIZE as usize - rust_ipl_header.len() - reset_vector_header.len()];
    let reloc = pe::relocate(
        &rust_ipl_bin[..],
        &mut new_rust_ipl_buf[..],
        // TD_SHIM_IPL_BASE as usize + rust_ipl_header.len(),
        // relocate ipl to 1M
        0x100000 as usize,
    );
    let entry_point = match reloc {
        Some(entry_point) => {
            println!(
                "reloc IPL entrypoint - 0x{:x} - base: 0x{:x}",
                entry_point,
                // TD_SHIM_IPL_BASE as usize + rust_ipl_header.len()
                // relocate ipl to 1M
                0x100000 as usize
            );
            (entry_point - 0x100000) as u32
        }
        None => panic!("reloc IPL fail"),
    };

    rust_firmware_file
        .write_all(&aug_buf[..TD_SHIM_MAILBOX_OFFSET as usize])
        .expect("fail to write pad");
    rust_firmware_file
        .write_all(&mailbox[..])
        .expect("fail to write pad");
    rust_firmware_file
        .write_all(
            &aug_buf[..(TD_SHIM_PAYLOAD_OFFSET as usize
                - TD_SHIM_MAILBOX_OFFSET as usize
                - mailbox.len())],
        )
        .expect("fail to write pad");

    rust_firmware_file
        .write_all(&rust_payload_header[..])
        .expect("fail to write rust payload header");
    if RELOCATE_PAYLOAD != 0 {
        rust_firmware_file
            .write_all(&new_rust_payload_buf[..])
            .expect("fail to write rust payload");
    } else {
        rust_firmware_file
            .write_all(&rust_payload_bin[..])
            .expect("fail to write rust payload");
        let pad_size = TD_SHIM_PAYLOAD_SIZE as usize
            - rust_payload_bin.len()
            - rust_payload_header.len()
            - metadata.len();
        rust_firmware_file
            .write_all(&zero_buf[..pad_size])
            .expect("fail to write pad");
    }
    rust_firmware_file
        .write_all(&metadata[..])
        .expect("fail to write pad");

    rust_firmware_file
        .write_all(&rust_ipl_header[..])
        .expect("fail to write rust IPL header");

    let current_data = rust_firmware_file.metadata().unwrap().len();

    #[derive(Debug, Pread, Pwrite)]
    struct ResetVectorParams {
        entry_point: u32, // rust entry point
        img_base: u32,    // rust ipl bin base
        img_size: u32,    // rust ipl bin size
    }

    let reset_vector_info = ResetVectorParams {
        entry_point,
        img_base: TD_SHIM_FIRMWARE_BASE + current_data as u32,
        img_size: rust_ipl_bin.len() as u32,
    };
    let reset_vector_info_buffer = &mut [0u8; size_of::<ResetVectorParams>()];
    let _ = reset_vector_info_buffer
        .pwrite(reset_vector_info, 0)
        .unwrap();

    rust_firmware_file
        .write_all(&new_rust_ipl_buf[..])
        .expect("fail to write rust IPL");

    rust_firmware_file
        .write_all(&reset_vector_header[..])
        .expect("fail to write reset vector header");

    rust_firmware_file
        .write_all(
            &reset_vector_bin[..(reset_vector_bin.len() - 0x20 - size_of::<ResetVectorParams>())],
        )
        .expect("fail to write reset vector");

    rust_firmware_file
        .write_all(&reset_vector_info_buffer[..])
        .expect("fail to write reset vector");

    rust_firmware_file
        .write_all(&metadata_ptr[..])
        .expect("fail to write reset vector");
    rust_firmware_file
        .write_all(&reset_vector_bin[(reset_vector_bin.len() - 0x1c)..])
        .expect("fail to write reset vector");

    rust_firmware_file.sync_data()?;

    Ok(())
}
