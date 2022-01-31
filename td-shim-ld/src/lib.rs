// Copyright (c) 2020 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::fs::{self, File};
use std::io::{self, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::ops::RangeInclusive;
use std::ptr::slice_from_raw_parts;

use log::{error, trace};
use scroll::{Pread, Pwrite};

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

const MAX_IPL_CONTENT_SIZE: usize =
    TD_SHIM_IPL_SIZE as usize - size_of::<IplFvHeaderByte>() - size_of::<ResetVectorHeader>();
const MAX_PAYLOAD_CONTENT_SIZE: usize =
    TD_SHIM_PAYLOAD_SIZE as usize - size_of::<PayloadFvHeaderByte>() - size_of::<TdxMetadata>();

fn write_u24(data: u32, buf: &mut [u8]) {
    assert!(data < 0xffffff);
    buf[0] = (data & 0xFF) as u8;
    buf[1] = ((data >> 8) & 0xFF) as u8;
    buf[2] = ((data >> 16) & 0xFF) as u8;
}

#[repr(C, align(4))]
#[derive(Copy, Clone, Debug, Pwrite)]
struct PayloadFvHeader {
    fv_header: FirmwareVolumeHeader,
    fv_block_map: [FvBlockMap; 2],
    pad_ffs_header: FfsFileHeader,
    fv_ext_header: FirmwareVolumeExtHeader,
    pad: [u8; 4],
}

impl Default for PayloadFvHeader {
    fn default() -> Self {
        let mut header_sz = [0u8; 3];
        write_u24(0x2c, &mut header_sz);

        PayloadFvHeader {
            fv_header: FirmwareVolumeHeader {
                zero_vector: [0u8; 16],
                file_system_guid: FIRMWARE_FILE_SYSTEM2_GUID.as_bytes().to_owned(),
                fv_length: 0,
                signature: FVH_SIGNATURE,
                attributes: 0x0004f6ff,
                header_length: 0x0048,
                checksum: 0,
                ext_header_offset: 0x0060,
                reserved: 0x00,
                revision: 0x02,
            },
            fv_block_map: [FvBlockMap::default(); 2],
            pad_ffs_header: FfsFileHeader {
                name: Guid::from_fields(
                    0x00000000,
                    0x0000,
                    0x0000,
                    0x00,
                    0x00,
                    &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                )
                .as_bytes()
                .to_owned(),
                integrity_check: 0xaae4,
                r#type: FV_FILETYPE_FFS_PAD,
                attributes: 0x00,
                size: header_sz,
                state: 0x07u8,
            },
            fv_ext_header: FirmwareVolumeExtHeader {
                fv_name: [0u8; 16],
                ext_header_size: 0,
            },
            pad: [0u8; 4],
        }
    }
}

#[repr(C, align(4))]
#[derive(Copy, Clone, Debug, Pread, Pwrite, Default)]
struct PayloadFvFfsHeader {
    ffs_header: FfsFileHeader,
}

#[repr(C, align(4))]
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

impl Default for PayloadFvHeaderByte {
    fn default() -> Self {
        PayloadFvHeaderByte {
            data: [0u8; size_of::<PayloadFvHeader>()
                + size_of::<PayloadFvFfsHeader>()
                + size_of::<PayloadFvFfsSectionHeader>()],
        }
    }
}

impl PayloadFvHeaderByte {
    fn build_tdx_payload_fv_header() -> Self {
        let mut hdr = Self::default();
        let fv_header_size = (size_of::<PayloadFvHeader>()) as usize;

        let mut tdx_payload_fv_header = PayloadFvHeader::default();
        tdx_payload_fv_header.fv_header.fv_length = TD_SHIM_PAYLOAD_SIZE as u64;
        tdx_payload_fv_header.fv_header.checksum = 0xdc0a;
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
        // Safe to unwrap() because space is enough.
        let res = hdr
            .data
            .pwrite(tdx_payload_fv_ffs_header, fv_header_size)
            .unwrap();
        assert_eq!(res, 24);

        let mut tdx_payload_fv_ffs_section_header = PayloadFvFfsSectionHeader::default();
        write_u24(
            TD_SHIM_PAYLOAD_SIZE - fv_header_size as u32 - size_of::<PayloadFvFfsHeader>() as u32,
            &mut tdx_payload_fv_ffs_section_header.section_header.size,
        );
        tdx_payload_fv_ffs_section_header.section_header.r#type = SECTION_PE32;
        // Safe to unwrap() because space is enough.
        let res = hdr
            .data
            .pwrite(
                tdx_payload_fv_ffs_section_header,
                fv_header_size + size_of::<PayloadFvFfsHeader>(),
            )
            .unwrap();
        assert_eq!(res, 4);

        hdr
    }

    // Build internal payload header
    fn build_tdx_ipl_fv_header() -> Self {
        let mut hdr = Self::default();
        let fv_header_size = (size_of::<PayloadFvHeader>()) as usize;

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
        tdx_ipl_fv_ffs_header.ffs_header.integrity_check = 0xaa0d;
        tdx_ipl_fv_ffs_header.ffs_header.r#type = FV_FILETYPE_SECURITY_CORE;
        tdx_ipl_fv_ffs_header.ffs_header.attributes = 0x00;
        write_u24(
            TD_SHIM_IPL_SIZE - fv_header_size as u32,
            &mut tdx_ipl_fv_ffs_header.ffs_header.size,
        );
        tdx_ipl_fv_ffs_header.ffs_header.state = 0x07u8;
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

type IplFvHeader = PayloadFvHeader;
type IplFvFfsHeader = PayloadFvFfsHeader;
type IplFvFfsSectionHeader = PayloadFvFfsSectionHeader;
type IplFvHeaderByte = PayloadFvHeaderByte;

fn build_tdx_metadata() -> TdxMetadata {
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

        // parameters
        tdx_metadata.payload_sections[1].data_offset = 0;
        tdx_metadata.payload_sections[1].raw_data_size = 0;
        tdx_metadata.payload_sections[1].memory_address = TD_PAYLOAD_PARAM_BASE as u64;
        tdx_metadata.payload_sections[1].memory_data_size = TD_PAYLOAD_PARAM_SIZE as u64;
        tdx_metadata.payload_sections[1].r#type = TDX_METADATA_SECTION_TYPE_PAYLOAD_PARAM;
        tdx_metadata.payload_sections[1].attributes = 0;
    }

    tdx_metadata
}

fn build_tdx_metadata_ptr() -> TdxMetadataPtr {
    let mut tdx_metadata_ptr = TdxMetadataPtr::default();
    tdx_metadata_ptr.ptr = TD_SHIM_METADATA_OFFSET;
    tdx_metadata_ptr
}

#[repr(C, align(4))]
#[derive(Debug, Default, Pwrite)]
struct ResetVectorHeader {
    ffs_header: FfsFileHeader,
    section_header_pad: CommonSectionHeader,
    pad: [u8; 8],
    section_header_reset_vector: CommonSectionHeader,
}

impl ResetVectorHeader {
    fn build_tdx_reset_vector_header() -> Self {
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

        tdx_reset_vector_header
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe {
            &*slice_from_raw_parts(
                self as *const ResetVectorHeader as *const u8,
                size_of::<Self>(),
            )
        }
    }
}

#[repr(C, align(4))]
#[derive(Debug, Pread, Pwrite)]
struct ResetVectorParams {
    entry_point: u32, // rust entry point
    img_base: u32,    // rust ipl bin base
    img_size: u32,    // rust ipl bin size
}

impl ResetVectorParams {
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            &*slice_from_raw_parts(
                self as *const ResetVectorParams as *const u8,
                size_of::<Self>(),
            )
        }
    }
}

struct InputData {
    data: Vec<u8>,
}

impl InputData {
    fn new(name: &str, range: RangeInclusive<usize>, desc: &str) -> io::Result<Self> {
        // Check file size first to avoid allocating too much memory.
        let md = fs::metadata(name).map_err(|e| {
            error!("Can not get metadata of file {}: {}", name, e);
            e
        })?;
        if md.len() > TD_SHIM_FIRMWARE_SIZE as u64 {
            error!(
                "Size of {} file ({}) is invalid, should be {}-{}",
                desc,
                md.len(),
                range.start(),
                range.end()
            );
            return Err(io::Error::new(io::ErrorKind::Other, "invalid file size"));
        }

        let data = fs::read(name).map_err(|e| {
            error!("Can not read data from file {}: {}", name, e);
            e
        })?;
        let len = data.len();
        if !range.contains(&len) {
            error!(
                "Size of {} file ({}) is invalid, should be {}-{}",
                desc,
                len,
                range.start(),
                range.end()
            );
            return Err(io::Error::new(io::ErrorKind::Other, "invalid file size"));
        }

        Ok(InputData { data })
    }
}

struct OutputFile {
    file: File,
    name: String,
}

impl OutputFile {
    fn new(name: &str) -> io::Result<Self> {
        let file = File::create(name).map_err(|e| {
            error!("Can not open output file {}: {}", name, e);
            e
        })?;

        Ok(Self {
            file,
            name: name.to_owned(),
        })
    }

    fn seek_and_write(&mut self, off: u64, data: &[u8], desc: &str) -> io::Result<()> {
        self.file
            .seek(SeekFrom::Start(off))
            .and(self.file.write_all(data))
            .map_err(|e| {
                error!("Can not write {} to file {}: {}", desc, self.name, e);
                e
            })
    }

    fn write(&mut self, data: &[u8], desc: &str) -> io::Result<()> {
        self.file.write_all(data).map_err(|e| {
            error!("Can not write {} to file {}: {}", desc, self.name, e);
            e
        })
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
    pub fn build(&self, reset_name: &str, ipl_name: &str, payload_name: &str) -> io::Result<()> {
        let reset_vector_bin = InputData::new(
            reset_name,
            TD_SHIM_RESET_VECTOR_SIZE as usize..=TD_SHIM_RESET_VECTOR_SIZE as usize,
            "reset_vector",
        )?;
        let ipl_bin = InputData::new(ipl_name, 0..=MAX_IPL_CONTENT_SIZE, "IPL")?;
        let payload_bin = InputData::new(payload_name, 0..=MAX_PAYLOAD_CONTENT_SIZE, "payload")?;
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

        let metadata = build_tdx_metadata();
        let pos = TD_SHIM_PAYLOAD_OFFSET as u64 + TD_SHIM_PAYLOAD_SIZE as u64
            - size_of::<TdxMetadata>() as u64;
        output_file.seek_and_write(pos, metadata.as_bytes(), "metadata")?;

        let ipl_header = IplFvHeaderByte::build_tdx_ipl_fv_header();
        output_file.seek_and_write(TD_SHIM_IPL_OFFSET as u64, &ipl_header.data, "IPL header")?;

        let mut ipl_reloc_buf = vec![0x00u8; MAX_IPL_CONTENT_SIZE];
        // relocate ipl to 1M
        let reloc = pe::relocate(&ipl_bin.data, &mut ipl_reloc_buf, 0x100000 as usize)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Can not relocate IPL content"))?;
        trace!(
            "reloc IPL entrypoint - 0x{:x} - base: 0x{:x}",
            reloc,
            0x100000
        );
        let entry_point = (reloc - 0x100000) as u32;
        let current_pos = output_file
            .file
            .metadata()
            .map_err(|e| {
                error!("Can not get size of file {}", output_file_name);
                e
            })?
            .len();
        let reset_vector_info = ResetVectorParams {
            entry_point,
            img_base: TD_SHIM_FIRMWARE_BASE + current_pos as u32,
            img_size: ipl_bin.data.len() as u32,
        };

        output_file.write(&ipl_reloc_buf, "internal payload content")?;

        let reset_vector_header = ResetVectorHeader::build_tdx_reset_vector_header();
        output_file.write(reset_vector_header.as_bytes(), "reset vector header")?;
        output_file.write(&reset_vector_bin.data, "reset vector content")?;

        // Overwrite the ResetVectorParams and TdxMetadataPtr.
        let pos = TD_SHIM_FIRMWARE_SIZE as u64 - 0x20 - size_of::<ResetVectorParams>() as u64;
        output_file.seek_and_write(pos, reset_vector_info.as_bytes(), "reset vector info")?;
        let metadata_ptr = build_tdx_metadata_ptr();
        output_file.write(metadata_ptr.as_bytes(), "metadata_ptr")?;

        output_file.file.sync_data()?;

        Ok(())
    }
}
