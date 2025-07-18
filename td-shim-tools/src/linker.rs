// Copyright (c) 2021-2025 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::cmp::min;
use std::fs::{self, File};
use std::io::{self, Write};
use std::mem::size_of;

use igvm::{
    IgvmDirectiveHeader, IgvmFile, IgvmInitializationHeader, IgvmPlatformHeader, IgvmRevision,
};
use igvm_defs::{
    IgvmPageDataFlags, IgvmPageDataType, IgvmPlatformType, IGVM_VHS_SUPPORTED_PLATFORM,
    PAGE_SIZE_4K,
};
use log::trace;
use r_efi::base::Guid;
use scroll::Pwrite;
use td_layout::build_time::{
    TD_SHIM_CONFIG_BASE, TD_SHIM_CONFIG_SIZE, TD_SHIM_FIRMWARE_BASE, TD_SHIM_FIRMWARE_SIZE,
    TD_SHIM_IPL_BASE, TD_SHIM_IPL_OFFSET, TD_SHIM_IPL_SIZE, TD_SHIM_MAILBOX_BASE,
    TD_SHIM_MAILBOX_OFFSET, TD_SHIM_MAILBOX_SIZE, TD_SHIM_METADATA_BASE, TD_SHIM_METADATA_OFFSET,
    TD_SHIM_METADATA_SIZE, TD_SHIM_PAYLOAD_BASE, TD_SHIM_PAYLOAD_OFFSET, TD_SHIM_PAYLOAD_SIZE,
    TD_SHIM_RESET_VECTOR_OFFSET, TD_SHIM_RESET_VECTOR_SIZE, TD_SHIM_SEC_CORE_INFO_OFFSET,
    TD_SHIM_TEMP_HEAP_BASE, TD_SHIM_TEMP_HEAP_SIZE, TD_SHIM_TEMP_STACK_BASE,
    TD_SHIM_TEMP_STACK_SIZE,
};
use td_layout::mailbox::TdxMpWakeupMailbox;
use td_loader::{elf, pe};
use td_shim::fv::{
    FvFfsFileHeader, FvFfsSectionHeader, FvHeader, IplFvFfsHeader, IplFvFfsSectionHeader,
    IplFvHeader,
};
use td_shim::reset_vector::{ResetVectorHeader, ResetVectorParams};
use td_shim::write_u24;
use td_shim_interface::metadata::{TdxMetadataGuid, TdxMetadataPtr};
use td_shim_interface::td_uefi_pi::pi::fv::{
    FfsFileHeader, FVH_REVISION, FVH_SIGNATURE, FV_FILETYPE_DXE_CORE, FV_FILETYPE_SECURITY_CORE,
    SECTION_PE32,
};

use crate::metadata::{default_metadata_sections, MetadataSections, TdxMetadata};
use crate::{InputData, OutputFile};

pub const MAX_IPL_CONTENT_SIZE: usize =
    TD_SHIM_IPL_SIZE as usize - size_of::<IplFvHeaderByte>() - size_of::<ResetVectorHeader>();
pub const MAX_PAYLOAD_CONTENT_SIZE: usize =
    TD_SHIM_PAYLOAD_SIZE as usize - size_of::<FvHeaderByte>();
pub const MAX_METADATA_CONFIG_SIZE: usize = 1024 * 1024;
const MEMORY_4G: u64 = 0x1_0000_0000;

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
        tdx_ipl_fv_header.fv_header.update_checksum();
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

pub fn build_tdx_metadata(
    path: Option<&str>,
    payload_type: PayloadType,
) -> io::Result<TdxMetadata> {
    let sections = if let Some(path) = path {
        let metadata_config = fs::read(path)?;
        serde_json::from_slice::<MetadataSections>(metadata_config.as_slice())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
    } else {
        default_metadata_sections(payload_type)
    };

    TdxMetadata::new(sections).ok_or(io::Error::new(
        io::ErrorKind::Other,
        "Fail to create metadata",
    ))
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageFormat {
    TDVF,
    IGVM,
}

impl Default for ImageFormat {
    fn default() -> Self {
        Self::TDVF
    }
}

impl std::str::FromStr for ImageFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tdvf" => Ok(ImageFormat::TDVF),
            "igvm" => Ok(ImageFormat::IGVM),
            _ => return Err(format!("Invalid output file type: {}", s)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadType {
    Linux,
    Executable,
}

impl Default for PayloadType {
    fn default() -> Self {
        Self::Linux
    }
}

impl std::str::FromStr for PayloadType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "linux" => Ok(PayloadType::Linux),
            "executable" => Ok(PayloadType::Executable),
            _ => return Err(format!("Invalid payload type: {}", s)),
        }
    }
}

fn insert_igvm_pages(
    directive_headers: &mut Vec<IgvmDirectiveHeader>,
    base: u64,
    size: u64,
    data: &Vec<u8>,
    unmeasured: bool,
) {
    let num_pages = size / PAGE_SIZE_4K;
    for i in 0..num_pages {
        let start = (i * PAGE_SIZE_4K) as usize;
        let end = min(((i + 1) * PAGE_SIZE_4K) as usize, data.len());
        let page_data = if data.len() == 0 {
            vec![]
        } else {
            if start < end {
                data[start..end].to_vec()
            } else {
                vec![0u8; PAGE_SIZE_4K as usize]
            }
        };
        let mut flags = IgvmPageDataFlags::new();
        if unmeasured {
            flags.set_unmeasured(true);
        }
        directive_headers.push(IgvmDirectiveHeader::PageData {
            gpa: base + i * PAGE_SIZE_4K,
            compatibility_mask: 1,
            flags: flags,
            data_type: IgvmPageDataType::NORMAL,
            data: page_data,
        });
    }
}

/// TD shim linker to compose multiple components into the final shim binary.
#[derive(Default)]
pub struct TdShimLinker {
    payload_relocation: bool,
    output_file_name: Option<String>,
    image_format: Option<ImageFormat>,
    payload_type: PayloadType,
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

    /// Set image format.
    pub fn set_image_format(&mut self, image_format: ImageFormat) -> &mut Self {
        self.image_format = Some(image_format);
        self
    }

    /// Enable/disable relocation of shim payload.
    pub fn set_payload_type(&mut self, payload_type: PayloadType) -> &mut Self {
        self.payload_type = payload_type;
        self
    }

    /// Build the shim binary.
    pub fn build(
        &self,
        reset_name: &str,
        ipl_name: &str,
        payload_name: Option<&str>,
        metadata_name: Option<&str>,
    ) -> io::Result<()> {
        match self.image_format.unwrap_or_default() {
            ImageFormat::TDVF => self.build_tdvf(reset_name, ipl_name, payload_name, metadata_name),
            ImageFormat::IGVM => self.build_igvm(reset_name, ipl_name, payload_name, metadata_name),
        }
    }

    fn build_igvm(
        &self,
        reset_name: &str,
        ipl_name: &str,
        payload_name: Option<&str>,
        metadata_name: Option<&str>,
    ) -> io::Result<()> {
        let mut directive_headers: Vec<IgvmDirectiveHeader> = Vec::new();

        insert_igvm_pages(
            &mut directive_headers,
            TD_SHIM_CONFIG_BASE as u64,
            TD_SHIM_CONFIG_SIZE as u64,
            &vec![],
            false,
        );

        insert_igvm_pages(
            &mut directive_headers,
            TD_SHIM_MAILBOX_BASE as u64,
            TD_SHIM_MAILBOX_SIZE as u64,
            &vec![],
            false,
        );

        insert_igvm_pages(
            &mut directive_headers,
            TD_SHIM_TEMP_STACK_BASE as u64,
            TD_SHIM_TEMP_STACK_SIZE as u64,
            &vec![],
            false,
        );

        insert_igvm_pages(
            &mut directive_headers,
            TD_SHIM_TEMP_HEAP_BASE as u64,
            TD_SHIM_TEMP_HEAP_SIZE as u64,
            &vec![],
            false,
        );

        if let Some(payload_name) = payload_name {
            let payload_bin =
                InputData::new(payload_name, 0..=MAX_PAYLOAD_CONTENT_SIZE, "payload")?;
            let payload_header = PayloadFvHeaderByte::build_tdx_payload_fv_header();
            let mut payload_data = payload_header.data.to_vec();
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
                payload_data.extend_from_slice(&payload_reloc_buf);
            } else {
                payload_data.extend_from_slice(&payload_bin.data);
            }
            insert_igvm_pages(
                &mut directive_headers,
                TD_SHIM_PAYLOAD_BASE as u64,
                TD_SHIM_PAYLOAD_SIZE as u64,
                &payload_data,
                true,
            );
        }

        let metadata = build_tdx_metadata(metadata_name, self.payload_type)?.to_vec();

        let ipl_header = IplFvHeaderByte::build_tdx_ipl_fv_header();
        let ipl_bin = InputData::new(ipl_name, 0..=MAX_IPL_CONTENT_SIZE, "IPL")?;
        let mut ipl_reloc_buf = vec![0x00u8; MAX_IPL_CONTENT_SIZE];
        // relocate ipl to 1M
        const SIZE_1MB: u64 = 0x100000;
        let reloc = elf::relocate_elf_with_per_program_header(
            &ipl_bin.data,
            &mut ipl_reloc_buf,
            SIZE_1MB as usize,
        )
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Can not relocate IPL content"))?;
        trace!(
            "reloc IPL entrypoint - 0x{:x} - base: 0x{:x}",
            reloc.0,
            SIZE_1MB
        );
        let mut ipl_data = ipl_header.data.to_vec();
        ipl_data.extend(ipl_reloc_buf);

        let reset_vector_header = ResetVectorHeader::build_tdx_reset_vector_header();
        let reset_vector_bin = InputData::new(
            reset_name,
            TD_SHIM_RESET_VECTOR_SIZE as usize..=TD_SHIM_RESET_VECTOR_SIZE as usize,
            "reset_vector",
        )?;
        let mut reset_vector_data = reset_vector_header.as_bytes().to_vec();
        reset_vector_data.extend(&reset_vector_bin.data);
        let entry_point = (reloc.0 - SIZE_1MB) as u32;
        // Overwrite the ResetVectorParams and TdxMetadataPtr.
        let reset_vector_info = ResetVectorParams {
            entry_point,
            img_base: TD_SHIM_IPL_BASE + ipl_header.data.len() as u32,
            img_size: ipl_bin.data.len() as u32,
        };
        let start = (TD_SHIM_SEC_CORE_INFO_OFFSET - TD_SHIM_RESET_VECTOR_OFFSET) as usize
            + reset_vector_header.as_bytes().len();
        let end = start + reset_vector_info.as_bytes().len();
        reset_vector_data.splice(start..end, reset_vector_info.as_bytes().to_vec());
        // Overwrite the OVMF GUID table to be compatible with QEMU
        let ovmf_guid_table = build_ovmf_guid_table();
        assert_eq!(
            ovmf_guid_table.len(),
            (TD_SHIM_FIRMWARE_SIZE - TD_SHIM_SEC_CORE_INFO_OFFSET) as usize
                - size_of::<ResetVectorParams>()
                - 0x20
        );
        let start = end;
        let end = start + ovmf_guid_table.len();
        reset_vector_data.splice(start..end, ovmf_guid_table.to_vec());
        let metadata_ptr = build_tdx_metadata_ptr();
        let start = end;
        let end = start + metadata_ptr.as_bytes().len();
        reset_vector_data.splice(start..end, metadata_ptr.as_bytes().to_vec());

        let bfv_size =
            (TD_SHIM_METADATA_SIZE + TD_SHIM_IPL_SIZE + TD_SHIM_RESET_VECTOR_SIZE) as usize;
        let mut bfv_data = vec![0u8; bfv_size as usize];

        let start = 0 as usize;
        let end = start + metadata.len();
        bfv_data.splice(start..end, metadata);

        let start = (TD_SHIM_IPL_OFFSET - TD_SHIM_METADATA_OFFSET) as usize;
        let end = start + ipl_data.len();
        bfv_data.splice(start..end, ipl_data);

        let start = (TD_SHIM_RESET_VECTOR_OFFSET - TD_SHIM_METADATA_OFFSET) as usize
            - reset_vector_header.as_bytes().len();
        let end = start + reset_vector_data.len();
        bfv_data.splice(start..end, reset_vector_data);

        insert_igvm_pages(
            &mut directive_headers,
            TD_SHIM_METADATA_BASE as u64,
            bfv_size as u64,
            &bfv_data,
            true,
        );

        if (TD_SHIM_FIRMWARE_BASE as u64 + TD_SHIM_FIRMWARE_SIZE as u64) < MEMORY_4G {
            let size = PAGE_SIZE_4K as u64;
            let base = MEMORY_4G - size;
            let start = bfv_data.len() - size as usize;
            insert_igvm_pages(
                &mut directive_headers,
                base,
                size,
                &bfv_data[start..].to_vec(),
                true,
            );
        }

        let platform_header = IgvmPlatformHeader::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
            compatibility_mask: 1,
            highest_vtl: 0,
            platform_type: IgvmPlatformType::TDX,
            platform_version: 1,
            shared_gpa_boundary: 1u64 << 47,
        });

        let initialization_headers = vec![IgvmInitializationHeader::GuestPolicy {
            policy: 0,
            compatibility_mask: 1,
        }];

        let igvm = IgvmFile::new(
            IgvmRevision::V1,
            vec![platform_header],
            initialization_headers,
            directive_headers,
        )
        .unwrap();

        let mut output: Vec<u8> = Vec::new();
        igvm.serialize(&mut output).unwrap();

        let output_file_name = self
            .output_file_name
            .as_ref()
            .map(|v| v.as_str())
            .unwrap_or("td_shim.igvm");
        let mut file = File::create(output_file_name).unwrap();
        file.write_all(&output).unwrap();

        io::Result::Ok(())
    }

    fn build_tdvf(
        &self,
        reset_name: &str,
        ipl_name: &str,
        payload_name: Option<&str>,
        metadata_name: Option<&str>,
    ) -> io::Result<()> {
        assert!(
            (TD_SHIM_FIRMWARE_BASE as u64 + TD_SHIM_FIRMWARE_SIZE as u64) == MEMORY_4G,
            "FW top must be 4GB for TDVF images",
        );

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

        let metadata = build_tdx_metadata(metadata_name, self.payload_type)?;
        let pos = TD_SHIM_METADATA_OFFSET as u64;
        output_file.seek_and_write(pos, &metadata.to_vec(), "metadata")?;

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
