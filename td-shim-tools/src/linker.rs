// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::io;
use std::mem::size_of;

use log::trace;
use r_efi::base::Guid;
use scroll::Pwrite;
use td_layout::build_time::{
    TD_SHIM_CONFIG_BASE, TD_SHIM_CONFIG_OFFSET, TD_SHIM_CONFIG_SIZE, TD_SHIM_FIRMWARE_BASE,
    TD_SHIM_FIRMWARE_SIZE, TD_SHIM_IPL_OFFSET, TD_SHIM_IPL_SIZE, TD_SHIM_MAILBOX_BASE,
    TD_SHIM_MAILBOX_OFFSET, TD_SHIM_MAILBOX_SIZE, TD_SHIM_METADATA_OFFSET, TD_SHIM_METADATA_SIZE,
    TD_SHIM_PAYLOAD_BASE, TD_SHIM_PAYLOAD_OFFSET, TD_SHIM_PAYLOAD_SIZE, TD_SHIM_RESET_VECTOR_SIZE,
    TD_SHIM_SEC_CORE_INFO_OFFSET, TD_SHIM_TEMP_HEAP_BASE, TD_SHIM_TEMP_HEAP_SIZE,
    TD_SHIM_TEMP_STACK_BASE, TD_SHIM_TEMP_STACK_SIZE,
};
use td_layout::mailbox::TdxMpWakeupMailbox;
#[cfg(feature = "boot-kernel")]
use td_layout::runtime::{KERNEL_BASE, KERNEL_PARAM_BASE, KERNEL_PARAM_SIZE, KERNEL_SIZE};
use td_layout::runtime::{TD_HOB_BASE, TD_HOB_SIZE};
use td_loader::{elf, pe};
use td_shim::fv::{
    FvFfsFileHeader, FvFfsSectionHeader, FvHeader, IplFvFfsHeader, IplFvFfsSectionHeader,
    IplFvHeader,
};
use td_shim::metadata::{
    TdxMetadata, TdxMetadataGuid, TdxMetadataPtr, TDX_METADATA_ATTRIBUTES_EXTENDMR,
    TDX_METADATA_SECTION_TYPE_BFV, TDX_METADATA_SECTION_TYPE_CFV,
    TDX_METADATA_SECTION_TYPE_PERM_MEM, TDX_METADATA_SECTION_TYPE_TD_HOB,
    TDX_METADATA_SECTION_TYPE_TEMP_MEM,
};
#[cfg(feature = "boot-kernel")]
use td_shim::metadata::{
    TDX_METADATA_SECTION_TYPE_PAYLOAD, TDX_METADATA_SECTION_TYPE_PAYLOAD_PARAM,
};
use td_shim::reset_vector::{ResetVectorHeader, ResetVectorParams};
use td_shim::write_u24;
use td_uefi_pi::pi::fv::{
    FfsFileHeader, FVH_REVISION, FVH_SIGNATURE, FV_FILETYPE_DXE_CORE, FV_FILETYPE_SECURITY_CORE,
    SECTION_PE32,
};

use crate::{InputData, OutputFile};

pub const MAX_IPL_CONTENT_SIZE: usize =
    TD_SHIM_IPL_SIZE as usize - size_of::<IplFvHeaderByte>() - size_of::<ResetVectorHeader>();
pub const MAX_PAYLOAD_CONTENT_SIZE: usize =
    TD_SHIM_PAYLOAD_SIZE as usize - size_of::<FvHeaderByte>();

pub const OVMF_TABLE_FOOTER_GUID: Guid = Guid::from_fields(
    0x96b582de,
    0x1fb2,
    0x45f7,
    0xba,
    0xea,
    &[0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d],
);

pub const OVMF_TABLE_TDX_METADATA_GUID: Guid = Guid::from_fields(
    0xe47a6535,
    0x984a,
    0x4798,
    0x86,
    0x5e,
    &[0x46, 0x85, 0xa7, 0xbf, 0x8e, 0xc2],
);

#[repr(C, align(4))]
pub struct FvHeaderByte {
    pub data: [u8; size_of::<FvHeader>()
        + size_of::<FvFfsFileHeader>()
        + size_of::<FvFfsSectionHeader>()],
}

impl Default for FvHeaderByte {
    fn default() -> Self {
        FvHeaderByte {
            data: [0u8; size_of::<FvHeader>()
                + size_of::<FvFfsFileHeader>()
                + size_of::<FvFfsSectionHeader>()],
        }
    }
}

impl FvHeaderByte {
    pub fn build_tdx_payload_fv_header() -> Self {
        let mut hdr = Self::default();
        let fv_header_size = (size_of::<FvHeader>()) as usize;

        let mut tdx_payload_fv_header = FvHeader::default();
        tdx_payload_fv_header.fv_header.fv_length = TD_SHIM_PAYLOAD_SIZE as u64;
        tdx_payload_fv_header.fv_header.signature = FVH_SIGNATURE;
        tdx_payload_fv_header.fv_header.header_length = size_of::<FvHeader>() as u16;
        tdx_payload_fv_header.fv_header.revision = FVH_REVISION;
        tdx_payload_fv_header.fv_header.update_checksum();

        tdx_payload_fv_header.fv_block_map[0].num_blocks = (TD_SHIM_PAYLOAD_SIZE as u32) / 0x1000;
        tdx_payload_fv_header.fv_block_map[0].length = 0x1000;
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
        // Safe to unwrap() because space is enough.
        let res = hdr.data.pwrite(tdx_payload_fv_header, 0).unwrap();
        assert_eq!(res, 120);

        let mut tdx_payload_fv_ffs_header = FvFfsFileHeader::default();
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
        tdx_payload_fv_ffs_header.ffs_header.r#type = FV_FILETYPE_DXE_CORE;
        tdx_payload_fv_ffs_header.ffs_header.attributes = 0x00;
        write_u24(
            TD_SHIM_PAYLOAD_SIZE - fv_header_size as u32,
            &mut tdx_payload_fv_ffs_header.ffs_header.size,
        );
        tdx_payload_fv_ffs_header.ffs_header.update_checksum();
        // Safe to unwrap() because space is enough.
        let res = hdr
            .data
            .pwrite(tdx_payload_fv_ffs_header, fv_header_size)
            .unwrap();
        assert_eq!(res, 24);

        let mut tdx_payload_fv_ffs_section_header = FvFfsSectionHeader::default();
        write_u24(
            TD_SHIM_PAYLOAD_SIZE - fv_header_size as u32 - size_of::<FvFfsFileHeader>() as u32,
            &mut tdx_payload_fv_ffs_section_header.section_header.size,
        );
        tdx_payload_fv_ffs_section_header.section_header.r#type = SECTION_PE32;
        // Safe to unwrap() because space is enough.
        let res = hdr
            .data
            .pwrite(
                tdx_payload_fv_ffs_section_header,
                fv_header_size + size_of::<FvFfsFileHeader>(),
            )
            .unwrap();
        assert_eq!(res, 4);

        hdr
    }

    // Build internal payload header
    pub fn build_tdx_ipl_fv_header() -> Self {
        let mut hdr = Self::default();
        let fv_header_size = (size_of::<FvHeader>()) as usize;

        let mut tdx_ipl_fv_header = IplFvHeader::default();
        tdx_ipl_fv_header.fv_header.fv_length =
            (TD_SHIM_IPL_SIZE + TD_SHIM_RESET_VECTOR_SIZE) as u64;
        tdx_ipl_fv_header.fv_header.checksum = 0x3d21;
        tdx_ipl_fv_header.fv_block_map[0].num_blocks =
            (TD_SHIM_IPL_SIZE + TD_SHIM_RESET_VECTOR_SIZE) / 0x1000;
        tdx_ipl_fv_header.fv_block_map[0].length = 0x1000;
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
        // Safe to unwrap() because space is enough.
        let res = hdr.data.pwrite(tdx_ipl_fv_header, 0).unwrap();
        assert_eq!(res, 120);

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

        tdx_ipl_fv_ffs_header.ffs_header.r#type = FV_FILETYPE_SECURITY_CORE;
        tdx_ipl_fv_ffs_header.ffs_header.attributes = 0x00;
        write_u24(
            TD_SHIM_IPL_SIZE - fv_header_size as u32,
            &mut tdx_ipl_fv_ffs_header.ffs_header.size,
        );
        tdx_ipl_fv_ffs_header.ffs_header.update_checksum();
        // Safe to unwrap() because space is enough.
        let res = hdr
            .data
            .pwrite(tdx_ipl_fv_ffs_header, fv_header_size)
            .unwrap();
        assert_eq!(res, 24);

        let mut tdx_ipl_fv_ffs_section_header = IplFvFfsSectionHeader::default();
        write_u24(
            TD_SHIM_IPL_SIZE - fv_header_size as u32 - size_of::<FfsFileHeader>() as u32,
            &mut tdx_ipl_fv_ffs_section_header.section_header.size,
        );
        tdx_ipl_fv_ffs_section_header.section_header.r#type = SECTION_PE32;
        // Safe to unwrap() because space is enough.
        let res = hdr
            .data
            .pwrite(
                tdx_ipl_fv_ffs_section_header,
                fv_header_size + size_of::<IplFvFfsHeader>(),
            )
            .unwrap();
        assert_eq!(res, 4);

        hdr
    }
}

pub type PayloadFvHeaderByte = FvHeaderByte;
pub type IplFvHeaderByte = FvHeaderByte;

pub fn build_tdx_metadata() -> TdxMetadata {
    let mut tdx_metadata = TdxMetadata::default();

    // BFV
    tdx_metadata.sections[0].data_offset = TD_SHIM_PAYLOAD_OFFSET;
    let data_size = (TD_SHIM_PAYLOAD_SIZE
        + TD_SHIM_IPL_SIZE
        + TD_SHIM_RESET_VECTOR_SIZE
        + TD_SHIM_METADATA_SIZE) as u64;
    tdx_metadata.sections[0].raw_data_size = data_size as u32;
    tdx_metadata.sections[0].memory_address = TD_SHIM_PAYLOAD_BASE as u64;
    tdx_metadata.sections[0].memory_data_size = data_size;
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
    tdx_metadata.sections[4].memory_address = TD_HOB_BASE as u64;
    tdx_metadata.sections[4].memory_data_size = TD_HOB_SIZE as u64;
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
        tdx_metadata.payload_sections[0].memory_address = KERNEL_BASE as u64;
        tdx_metadata.payload_sections[0].memory_data_size = KERNEL_SIZE as u64;
        tdx_metadata.payload_sections[0].r#type = TDX_METADATA_SECTION_TYPE_PAYLOAD;
        tdx_metadata.payload_sections[0].attributes = 0;

        // parameters
        tdx_metadata.payload_sections[1].data_offset = 0;
        tdx_metadata.payload_sections[1].raw_data_size = 0;
        tdx_metadata.payload_sections[1].memory_address = KERNEL_PARAM_BASE as u64;
        tdx_metadata.payload_sections[1].memory_data_size = KERNEL_PARAM_SIZE as u64;
        tdx_metadata.payload_sections[1].r#type = TDX_METADATA_SECTION_TYPE_PAYLOAD_PARAM;
        tdx_metadata.payload_sections[1].attributes = 0;
    }

    tdx_metadata
}

pub fn build_ovmf_guid_table() -> Vec<u8> {
    let mut table = Vec::new();

    let metadata_offset =
        TD_SHIM_FIRMWARE_SIZE - (TD_SHIM_METADATA_OFFSET + size_of::<TdxMetadataGuid>() as u32);
    let metadata_block_size = size_of::<u32>() + size_of::<u16>() + size_of::<Guid>();

    // The data layout of the entry is:
    //   - arbitrary length data
    //   - 2 byte length of the block (guid + data length + 2)
    //   - 16 byte guid
    table.extend_from_slice(&u32::to_le_bytes(metadata_offset));
    table.extend_from_slice(&u16::to_le_bytes(metadata_block_size as u16));
    table.extend_from_slice(OVMF_TABLE_TDX_METADATA_GUID.as_bytes());

    let guided_table_size = metadata_block_size + size_of::<u16>() + size_of::<Guid>();
    // The data layout of the entry is:
    //   - 2 byte length of of the whole table
    //   - 16 byte guid
    table.extend_from_slice(&u16::to_le_bytes(guided_table_size as u16));
    table.extend_from_slice(OVMF_TABLE_FOOTER_GUID.as_bytes());

    table
}

pub fn build_tdx_metadata_ptr() -> TdxMetadataPtr {
    TdxMetadataPtr {
        //     +---------------------+ <- TdxMetadataGuid TD_SHIM_METADATA_OFFSET
        //     |   TdxMetadataGuid   |
        //     +---------------------+ <- TdxMetadataDescriptor
        //     |TdxMetadataDescriptor|
        //     |         ...         |
        //     +---------------------+
        // See: https://github.com/confidential-containers/td-shim/blob/23e33997b104234b16940baf0c27f57350dafd66/doc/tdshim_spec.md
        // Table 1.1-1 TDVF_DESCRIPTOR definition
        ptr: TD_SHIM_METADATA_OFFSET + size_of::<TdxMetadataGuid>() as u32,
    }
}

/// TD shim linker to compose multiple components into the final shim binary.
#[derive(Default)]
pub struct TdShimLinker {
    payload_relocation: bool,
    output_file_name: Option<String>,
}

impl TdShimLinker {
    /// Enable/disable relocation of shim payload.
    pub fn set_payload_relocation(&mut self, relocation: bool) -> &mut Self {
        self.payload_relocation = relocation;
        self
    }

    /// Set file name for the generated shim binary.
    pub fn set_output_file(&mut self, name: String) -> &mut Self {
        self.output_file_name = Some(name);
        self
    }

    /// Build the shim binary.
    pub fn build(
        &self,
        reset_name: &str,
        ipl_name: &str,
        payload_name: Option<&str>,
    ) -> io::Result<()> {
        let reset_vector_bin = InputData::new(
            reset_name,
            TD_SHIM_RESET_VECTOR_SIZE as usize..=TD_SHIM_RESET_VECTOR_SIZE as usize,
            "reset_vector",
        )?;
        let ipl_bin = InputData::new(ipl_name, 0..=MAX_IPL_CONTENT_SIZE, "IPL")?;
        let output_file_name = self
            .output_file_name
            .as_ref()
            .map(|v| v.as_str())
            .unwrap_or("td_shim.bin");
        let mut output_file = OutputFile::new(output_file_name)?;

        let mailbox = TdxMpWakeupMailbox::default();
        output_file.seek_and_write(
            TD_SHIM_MAILBOX_OFFSET as u64,
            mailbox.as_bytes(),
            "mailbox content",
        )?;

        if let Some(payload_name) = payload_name {
            let payload_bin =
                InputData::new(payload_name, 0..=MAX_PAYLOAD_CONTENT_SIZE, "payload")?;
            let payload_header = PayloadFvHeaderByte::build_tdx_payload_fv_header();
            output_file.seek_and_write(
                TD_SHIM_PAYLOAD_OFFSET as u64,
                &payload_header.data,
                "payload header",
            )?;

            if self.payload_relocation {
                let mut payload_reloc_buf = vec![0x0u8; MAX_PAYLOAD_CONTENT_SIZE];
                let reloc = pe::relocate(
                    &payload_bin.data,
                    &mut payload_reloc_buf,
                    TD_SHIM_PAYLOAD_BASE as usize + payload_header.data.len(),
                )
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::Other, "Can not relocate payload content")
                })?;
                trace!("shim payload relocated to 0x{:x}", reloc);
                output_file.write(&payload_reloc_buf, "payload content")?;
            } else {
                output_file.write(&payload_bin.data, "payload content")?;
            }
        }

        let metadata = build_tdx_metadata();
        let pos = TD_SHIM_METADATA_OFFSET as u64;
        output_file.seek_and_write(pos, metadata.as_bytes(), "metadata")?;

        let ipl_header = IplFvHeaderByte::build_tdx_ipl_fv_header();
        output_file.seek_and_write(TD_SHIM_IPL_OFFSET as u64, &ipl_header.data, "IPL header")?;

        let mut ipl_reloc_buf = vec![0x00u8; MAX_IPL_CONTENT_SIZE];
        // relocate ipl to 1M
        let reloc = elf::relocate_elf_with_per_program_header(
            &ipl_bin.data,
            &mut ipl_reloc_buf,
            0x100000 as usize,
        )
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Can not relocate IPL content"))?;
        trace!(
            "reloc IPL entrypoint - 0x{:x} - base: 0x{:x}",
            reloc.0,
            0x100000
        );
        let entry_point = (reloc.0 - 0x100000) as u32;
        let current_pos = output_file.current_pos()?;
        let reset_vector_info = ResetVectorParams {
            entry_point,
            img_base: TD_SHIM_FIRMWARE_BASE + current_pos as u32,
            img_size: ipl_bin.data.len() as u32,
        };

        output_file.write(&ipl_reloc_buf, "internal payload content")?;

        let reset_vector_header = ResetVectorHeader::build_tdx_reset_vector_header();
        output_file.write(reset_vector_header.as_bytes(), "reset vector header")?;
        output_file.write(&reset_vector_bin.data, "reset vector content")?;

        let current_pos = output_file.current_pos()?;
        assert_eq!(current_pos, TD_SHIM_FIRMWARE_SIZE as u64);

        // Overwrite the ResetVectorParams and TdxMetadataPtr.
        let pos = TD_SHIM_SEC_CORE_INFO_OFFSET as u64;
        output_file.seek_and_write(pos, reset_vector_info.as_bytes(), "SEC Core info")?;

        // Overwrite the OVMF GUID table to be compatible with QEMU
        let ovmf_guid_table = build_ovmf_guid_table();
        assert_eq!(
            ovmf_guid_table.len(),
            (TD_SHIM_FIRMWARE_SIZE - TD_SHIM_SEC_CORE_INFO_OFFSET) as usize
                - size_of::<ResetVectorParams>()
                - 0x20
        );
        output_file.write(ovmf_guid_table.as_slice(), "OVMF GUID table")?;

        let metadata_ptr = build_tdx_metadata_ptr();
        output_file.write(metadata_ptr.as_bytes(), "metadata_ptr")?;

        output_file.flush()?;

        Ok(())
    }
}
