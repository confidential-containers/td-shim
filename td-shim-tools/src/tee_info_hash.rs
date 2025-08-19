// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use core::fmt;
use igvm::{IgvmDirectiveHeader, IgvmFile};
use r_efi::base::Guid;
use scroll::Pread;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::mem::size_of;
use td_layout::build_time::{TD_SHIM_CONFIG_BASE, TD_SHIM_CONFIG_SIZE};
use td_shim_interface::metadata::*;
use zerocopy::FromBytes;
use zeroize::Zeroize;

#[derive(FromBytes)]
#[repr(C)]
pub struct IGVM_FIXED_HEADER {
    pub magic: u32,
    pub format_version: u32,
    pub variable_header_offset: u32,
    pub variable_header_size: u32,
    pub total_file_size: u32,
    pub checksum: u32,
}

pub const SHA384_DIGEST_SIZE: usize = 0x30;

const TDX_METADATA_ATTRIBUTES_EXTEND_MEM_PAGE_ADD: u32 = 0x2;

const TD_INFO_STRUCT_RESERVED_SIZE: usize = 0x70;
const TDVF_DESCRIPTOR_OFFSET: usize = 0x20;
const MRTD_EXTENSION_BUFFER_SIZE: usize = 0x80;
const TDH_MR_EXTEND_GRANULARITY: u64 = 0x100;
const PAGE_SIZE: u64 = 0x1_000;

const MEM_PAGE_ADD_ASCII_SIZE: usize = 0xc;
const MEM_PAGE_ADD_GPA_OFFSET: usize = 0x10;
const MEM_PAGE_ADD_GPA_SIZE: usize = 0x8;
const MR_EXTEND_ASCII_SIZE: usize = 0x9;
const MR_EXTEND_GPA_OFFSET: usize = 0x10;
const MR_EXTEND_GPA_SIZE: usize = 0x8;
const OVMF_TABLE_FOOTER_GUID_OFFSET: usize = 0x30;

const OVMF_TABLE_FOOTER_GUID: Guid = Guid::from_fields(
    0x96b5_82de,
    0x1fb2,
    0x45f7,
    0xba,
    0xea,
    &[0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d],
);

const OVMF_TABLE_TDX_METADATA_GUID: Guid = Guid::from_fields(
    0xe47a_6535,
    0x984a,
    0x4798,
    0x86,
    0x5e,
    &[0x46, 0x85, 0xa7, 0xbf, 0x8e, 0xc2],
);

pub struct TdvfDesc {
    pub signature: [u8; size_of::<u32>()],
    pub length: [u8; size_of::<u32>()],
    pub version: [u8; size_of::<u32>()],
    pub numberofsectionentry: [u8; size_of::<u32>()],
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Manifest {
    #[serde(with = "hex::serde")]
    pub attributes: [u8; size_of::<u64>()],
    #[serde(with = "hex::serde")]
    pub xfam: [u8; size_of::<u64>()],
    #[serde(with = "hex::serde")]
    pub mrconfigid: [u8; SHA384_DIGEST_SIZE],
    #[serde(with = "hex::serde")]
    pub mrowner: [u8; SHA384_DIGEST_SIZE],
    #[serde(with = "hex::serde")]
    pub mrownerconfig: [u8; SHA384_DIGEST_SIZE],
}

#[repr(C)]
#[derive(Debug)]
pub struct TdInfoStruct {
    /// TD's attributes
    pub attributes: [u8; size_of::<u64>()],
    /// TD's XFAM
    pub xfam: [u8; size_of::<u64>()],
    /// Measurement of the initial contents of the TD
    pub mrtd: [u8; SHA384_DIGEST_SIZE],
    /// Software-defined ID for non-owner-defined configuration of
    /// the guest TD
    pub mrconfig_id: [u8; SHA384_DIGEST_SIZE],
    /// Software-defined ID for the guest TD's owner
    pub mrowner: [u8; SHA384_DIGEST_SIZE],
    /// Software-defined ID for owner-defined configuration of
    /// the guest TD
    pub mrownerconfig: [u8; SHA384_DIGEST_SIZE],
    /// Runtime extendable measurement registers
    pub rtmr0: [u8; SHA384_DIGEST_SIZE],
    pub rtmr1: [u8; SHA384_DIGEST_SIZE],
    pub rtmr2: [u8; SHA384_DIGEST_SIZE],
    pub rtmr3: [u8; SHA384_DIGEST_SIZE],
    /// Reserved. Must be zero
    pub reserved: [u8; TD_INFO_STRUCT_RESERVED_SIZE],
}

impl Default for TdInfoStruct {
    fn default() -> Self {
        Self {
            attributes: Default::default(),
            xfam: Default::default(),
            mrtd: [0; SHA384_DIGEST_SIZE],
            mrconfig_id: [0; SHA384_DIGEST_SIZE],
            mrowner: [0; SHA384_DIGEST_SIZE],
            mrownerconfig: [0; SHA384_DIGEST_SIZE],
            rtmr0: [0; SHA384_DIGEST_SIZE],
            rtmr1: [0; SHA384_DIGEST_SIZE],
            rtmr2: [0; SHA384_DIGEST_SIZE],
            rtmr3: [0; SHA384_DIGEST_SIZE],
            reserved: [0; TD_INFO_STRUCT_RESERVED_SIZE],
        }
    }
}

impl fmt::Display for TdInfoStruct {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TdInfo:\n\tAttributes:\n\t{:x?}\n\txfam:\n\t{:x?}\n\
                        \tMR TD:\n\t{:x?}\n\tMR Config ID:\n\t{:x?}\n\
                        \tMR Owner:\n\t{:x?}\n\tMR Owner Config:\n\t{:x?}\n\
                        \tRTMR[0]:\n\t{:x?}\n\tRTMR[1]:\n\t{:x?}\n\
                        \tRTMR[2]:\n\t{:x?}\n\tRTMR[3]:\n\t{:x?}\n",
            self.attributes,
            self.xfam,
            self.mrtd,
            self.mrconfig_id,
            self.mrowner,
            self.mrownerconfig,
            self.rtmr0,
            self.rtmr1,
            self.rtmr2,
            self.rtmr3
        )
    }
}

impl TdInfoStruct {
    pub fn pack(self, buffer: &mut [u8; size_of::<TdInfoStruct>()]) -> usize {
        buffer.zeroize();
        let mut packed_size = 0;
        buffer[packed_size..packed_size + size_of::<u64>()].copy_from_slice(&self.attributes);
        packed_size += size_of::<u64>();
        buffer[packed_size..packed_size + size_of::<u64>()].copy_from_slice(&self.xfam);
        packed_size += size_of::<u64>();
        buffer[packed_size..packed_size + SHA384_DIGEST_SIZE].copy_from_slice(&self.mrtd);
        packed_size += SHA384_DIGEST_SIZE;
        buffer[packed_size..packed_size + SHA384_DIGEST_SIZE].copy_from_slice(&self.mrconfig_id);
        packed_size += SHA384_DIGEST_SIZE;
        buffer[packed_size..packed_size + SHA384_DIGEST_SIZE].copy_from_slice(&self.mrowner);
        packed_size += SHA384_DIGEST_SIZE;
        buffer[packed_size..packed_size + SHA384_DIGEST_SIZE].copy_from_slice(&self.mrownerconfig);
        packed_size += SHA384_DIGEST_SIZE;
        buffer[packed_size..packed_size + SHA384_DIGEST_SIZE].copy_from_slice(&self.rtmr0);
        packed_size += SHA384_DIGEST_SIZE;
        buffer[packed_size..packed_size + SHA384_DIGEST_SIZE].copy_from_slice(&self.rtmr1);
        packed_size += SHA384_DIGEST_SIZE;
        buffer[packed_size..packed_size + SHA384_DIGEST_SIZE].copy_from_slice(&self.rtmr2);
        packed_size += SHA384_DIGEST_SIZE;
        buffer[packed_size..packed_size + SHA384_DIGEST_SIZE].copy_from_slice(&self.rtmr3);
        packed_size += SHA384_DIGEST_SIZE;
        buffer[packed_size..packed_size + TD_INFO_STRUCT_RESERVED_SIZE]
            .copy_from_slice(&self.reserved);
        packed_size += TD_INFO_STRUCT_RESERVED_SIZE;
        packed_size
    }

    pub fn build_mrtd(&mut self, raw_image_file: &mut File, image_size: u64) {
        let mut metadata_off: u32 = 0;

        raw_image_file
            .seek(SeekFrom::Start(
                image_size - OVMF_TABLE_FOOTER_GUID_OFFSET as u64,
            ))
            .unwrap();

        let mut footer_guid_buf = [0; size_of::<Guid>()];
        raw_image_file.read_exact(&mut footer_guid_buf).unwrap();

        if OVMF_TABLE_FOOTER_GUID.as_bytes() == &footer_guid_buf {
            raw_image_file
                .seek(SeekFrom::Start(
                    image_size - OVMF_TABLE_FOOTER_GUID_OFFSET as u64 - size_of::<u16>() as u64,
                ))
                .unwrap();

            let table_len = raw_image_file.read_u16::<LittleEndian>().unwrap()
                - size_of::<Guid>() as u16
                - size_of::<u16>() as u16;
            let mut ovmf_table_offset =
                image_size - OVMF_TABLE_FOOTER_GUID_OFFSET as u64 - size_of::<u16>() as u64;

            let mut count: u16 = 0;
            while count < table_len {
                raw_image_file
                    .seek(SeekFrom::Start(
                        ovmf_table_offset - size_of::<Guid>() as u64,
                    ))
                    .unwrap();
                let mut guid_buf = [0; size_of::<Guid>()];
                raw_image_file.read_exact(&mut guid_buf).unwrap();

                raw_image_file
                    .seek(SeekFrom::Start(
                        ovmf_table_offset - size_of::<Guid>() as u64 - size_of::<u16>() as u64,
                    ))
                    .unwrap();
                let len = raw_image_file.read_u16::<LittleEndian>().unwrap();
                if OVMF_TABLE_TDX_METADATA_GUID.as_bytes() == &guid_buf {
                    raw_image_file
                        .seek(SeekFrom::Start(
                            ovmf_table_offset
                                - size_of::<Guid>() as u64
                                - size_of::<u16>() as u64
                                - size_of::<u32>() as u64,
                        ))
                        .unwrap();
                    metadata_off = image_size as u32
                        - raw_image_file.read_u32::<LittleEndian>().unwrap()
                        - size_of::<TdxMetadataGuid>() as u32;
                    break;
                }
                ovmf_table_offset -= len as u64;
                count += len;
            }
        } else {
            raw_image_file
                .seek(SeekFrom::Start(image_size - TDVF_DESCRIPTOR_OFFSET as u64))
                .unwrap();

            metadata_off = raw_image_file.read_u32::<LittleEndian>().unwrap()
                - size_of::<TdxMetadataGuid>() as u32;
        }

        raw_image_file
            .seek(SeekFrom::Start(metadata_off as u64))
            .unwrap();

        let mut desc_buf = [0; size_of::<TdxMetadataGuid>() + size_of::<TdxMetadataDescriptor>()];
        raw_image_file.read_exact(&mut desc_buf).unwrap();
        let desc = &desc_buf[size_of::<TdxMetadataGuid>()..];

        // Signature	        0	CHAR8[4]	    4	'TDVF' signature
        // Length	            4	UINT32	        4	Size of the structure (d)
        // Version	            8	UINT32	        4	Version of the structure. It must be 1.
        // NumberOfSectionEntry	12	UINT32	        4	Number of the section entry (n)
        // SectionEntries	    16	TDVF_SECTION[n]	32*n	See Table 1.1-2.
        let mut desc_offset = 0;
        let descriptor: TdxMetadataDescriptor = desc.pread(desc_offset).unwrap();
        if !(descriptor.is_valid()) {
            println!("{:?}", descriptor);
            panic!("The descriptor is not valid!\n");
        }

        raw_image_file
            .seek(SeekFrom::Start(
                metadata_off as u64 + size_of::<TdxMetadataGuid>() as u64,
            ))
            .unwrap();
        let mut metadata_buf = vec![0; descriptor.length as usize];
        raw_image_file.read_exact(&mut metadata_buf).unwrap();
        let desc = &metadata_buf[0..];

        desc_offset += size_of::<TdxMetadataDescriptor>();

        let mut buffer128: [u8; MRTD_EXTENSION_BUFFER_SIZE] = [0; MRTD_EXTENSION_BUFFER_SIZE]; // used by page add
        let mut buffer3_128: [[u8; MRTD_EXTENSION_BUFFER_SIZE]; 3] =
            [[0; MRTD_EXTENSION_BUFFER_SIZE]; 3]; // used by mr extend

        let mut sha384hasher = Sha384::new();

        for _i in 0..descriptor.number_of_section_entry {
            // DataOffset	    0	UINT32	4	The offset to the raw section in the binary image.
            // RawDataSize	    4	UINT32	4	The size of the raw section in the image.
            // MemoryAddress	8	UINT64	8	The guest physical address of the section loaded.
            // MemoryDataSize	16	UINT64	8	The size of the section loaded.
            // Type	            24	UINT32	4	The type of the TDVF_SECTION. See table 1.1-4.
            // Attributes	    28	UINT32	4	The attribute of the section. See Table 1.1-3.
            let sec: TdxMetadataSection = desc.pread(desc_offset).unwrap();
            desc_offset += size_of::<TdxMetadataSection>();

            // sanity check
            if sec.memory_address % PAGE_SIZE != 0 {
                panic!("Memory address must be 4K aligned!\n");
            }

            // MemoryAddress and MemoryDataSize shall be zero when the section type is TD_INFO
            if (sec.r#type != TDX_METADATA_SECTION_TYPE_TD_INFO)
                && (sec.memory_address != 0 || sec.memory_data_size != 0)
                && sec.memory_data_size < sec.raw_data_size as u64
            {
                panic!("Memory data size must exceed or equal the raw data size!\n");
            }

            if sec.memory_data_size % PAGE_SIZE != 0 {
                panic!("Memory data size must be 4K aligned!\n");
            }

            if sec.r#type >= TDX_METADATA_SECTION_TYPE_MAX {
                panic!("Invalid type value!\n");
            }

            let nr_pages = sec.memory_data_size / PAGE_SIZE;

            for iter in 0..nr_pages {
                if sec.attributes & TDX_METADATA_ATTRIBUTES_EXTEND_MEM_PAGE_ADD == 0 {
                    // Use TDCALL [TDH.MEM.PAGE.ADD]
                    fill_buffer128_with_mem_page_add(
                        &mut buffer128,
                        sec.memory_address + iter * PAGE_SIZE,
                    );

                    sha384hasher.update(buffer128);
                }

                // check attributes
                if sec.attributes & TDX_METADATA_ATTRIBUTES_EXTENDMR != 0 {
                    // Use TDCALL [TDH.MR.EXTEND]
                    let granularity = TDH_MR_EXTEND_GRANULARITY;
                    let iteration = PAGE_SIZE / granularity;
                    for chunk_iter in 0..iteration {
                        fill_buffer3_128_with_mr_extend(
                            &mut buffer3_128,
                            sec.memory_address + iter * PAGE_SIZE + chunk_iter * granularity,
                            raw_image_file,
                            sec.data_offset as u64 + iter * PAGE_SIZE + chunk_iter * granularity,
                        );

                        sha384hasher.update(buffer3_128[0]);
                        sha384hasher.update(buffer3_128[1]);
                        sha384hasher.update(buffer3_128[2]);
                    }
                }
            }
        }
        let hash = sha384hasher.finalize();
        self.mrtd.copy_from_slice(hash.as_slice());
    }

    pub fn build_igvmmrtd(&mut self, raw_image_file: &mut File) {
        let mut sha384hasher = Sha384::new();
        let mut contents = Vec::new();
        raw_image_file.read_to_end(&mut contents).unwrap();
        let igvm = IgvmFile::new_from_binary(&contents, None).expect("file parse error");
        let mut buffer128: [u8; MRTD_EXTENSION_BUFFER_SIZE] = [0; MRTD_EXTENSION_BUFFER_SIZE]; // used by page add
        let mut buffer3_128: [[u8; MRTD_EXTENSION_BUFFER_SIZE]; 3] =
            [[0; MRTD_EXTENSION_BUFFER_SIZE]; 3]; // used by mr extend

        for dir in igvm
            .directives()
            .iter()
            .filter(|x| matches! {x, IgvmDirectiveHeader::PageData { .. }})
        {
            if let IgvmDirectiveHeader::PageData {
                gpa,
                flags,
                data_type: _,
                compatibility_mask: _,
                data,
                ..
            } = dir
            {
                // Skip shared pages.
                if flags.shared() {
                    continue;
                }

                // Use TDCALL [TDH.MEM.PAGE.ADD]
                fill_buffer128_with_mem_page_add(&mut buffer128, *gpa);

                sha384hasher.update(buffer128);

                if !flags.unmeasured() {
                    // Hash the contents of the 4K page, 256 bytes at a time.
                    let page_data = data;
                    if (page_data.len() > 0) && (page_data.len() % PAGE_SIZE as usize == 0) {
                        // Use TDCALL [TDH.MR.EXTEND]
                        for offset in (0..PAGE_SIZE).step_by(TDH_MR_EXTEND_GRANULARITY as usize) {
                            fill_buffer3_128_with_mr_extend_tdvf(
                                &mut buffer3_128,
                                gpa + offset,
                                page_data,
                                offset as u64,
                            );

                            sha384hasher.update(buffer3_128[0]);
                            sha384hasher.update(buffer3_128[1]);
                            sha384hasher.update(buffer3_128[2]);
                        }
                    }
                }
            }
        }

        let hash = sha384hasher.finalize();
        println!("MRTD Hash: {:x?}", hash);
        self.mrtd.copy_from_slice(hash.as_slice());
    }

    pub fn read_igvmcfvdata(&mut self, raw_image_file: &mut File) -> Vec<u8> {
        let mut contents = Vec::new();
        let mut offset: usize = 0;
        let mut validpages: usize = 0;
        let mut cfv;
        raw_image_file.read_to_end(&mut contents).unwrap();
        let igvm = IgvmFile::new_from_binary(&contents, None).expect("file parse error");
        let fixed_header = IGVM_FIXED_HEADER::read_from_prefix(contents.as_slice())
            .expect("Invalid fixed header")
            .0; // TODO: zerocopy: use-rest-of-range (https://github.com/microsoft/openvmm/issues/759)

        for dir in igvm
            .directives()
            .iter()
            .filter(|x| matches! {x, IgvmDirectiveHeader::PageData { .. }})
        {
            if let IgvmDirectiveHeader::PageData {
                gpa,
                flags: _,
                data_type: _,
                compatibility_mask: _,
                data,
                ..
            } = dir
            {
                if *gpa >= TD_SHIM_CONFIG_BASE.into()
                    && *gpa < ((TD_SHIM_CONFIG_BASE + TD_SHIM_CONFIG_SIZE).into())
                {
                    if data.len() > 0 {
                        validpages += 1;
                    }
                    offset += 1;
                }
            }
        }
        // IGVM files deduplicates the pages, hence padding zeroes for configvolumesize
        let paddingbytes = TD_SHIM_CONFIG_SIZE as usize - (validpages * PAGE_SIZE as usize);
        offset = (fixed_header.variable_header_size + fixed_header.variable_header_offset) as usize;
        cfv = contents[offset..offset + (validpages * PAGE_SIZE as usize)].to_vec();
        cfv.extend(std::iter::repeat(0).take(paddingbytes));
        cfv
    }

    pub fn build_rtmr_with_seperator(&mut self, seperator: u32) {
        let seperator = u32::to_le_bytes(seperator);

        let mut sha384hasher = Sha384::new();
        sha384hasher.update(seperator);
        let hash = sha384hasher.finalize();

        let mut concat_input = [0u8; SHA384_DIGEST_SIZE * 2];
        concat_input[SHA384_DIGEST_SIZE..].copy_from_slice(hash.as_slice());

        let mut sha384hasher = Sha384::new();
        sha384hasher.update(concat_input);
        let hash = sha384hasher.finalize();

        self.rtmr0.copy_from_slice(hash.as_slice());
        self.rtmr1.copy_from_slice(hash.as_slice());
    }
}

fn fill_buffer128_with_mem_page_add(buf: &mut [u8; MRTD_EXTENSION_BUFFER_SIZE], gpa: u64) {
    buf.zeroize();

    // Byte 0 through 11 contain the ASCII string 'MEM.PAGE.ADD'.
    // Byte 16 through 23 contain the GPA (in little-endian format).
    // All the other bytes contain 0.
    buf[0..MEM_PAGE_ADD_ASCII_SIZE].copy_from_slice("MEM.PAGE.ADD".as_bytes());
    buf[MEM_PAGE_ADD_GPA_OFFSET..MEM_PAGE_ADD_GPA_OFFSET + MEM_PAGE_ADD_GPA_SIZE]
        .copy_from_slice(gpa.to_le_bytes().as_ref());
}

fn fill_buffer3_128_with_mr_extend(
    buf: &mut [[u8; MRTD_EXTENSION_BUFFER_SIZE]; 3],
    gpa: u64,
    file: &mut File,
    data_offset: u64,
) {
    buf[0].zeroize();
    buf[1].zeroize();
    buf[2].zeroize();

    // Byte 0 through 8 contain the ASCII string 'MR.EXTEND'.
    // Byte 16 through 23 contain the GPA (in little-endian format).
    // All the other bytes contain 0. The other two extension buffers contain the chunk’s content.
    buf[0][0..MR_EXTEND_ASCII_SIZE].copy_from_slice("MR.EXTEND".as_bytes());
    buf[0][MR_EXTEND_GPA_OFFSET..MR_EXTEND_GPA_OFFSET + MR_EXTEND_GPA_SIZE]
        .copy_from_slice(gpa.to_le_bytes().as_ref());

    file.seek(SeekFrom::Start(data_offset)).unwrap();
    file.read_exact(&mut buf[1]).unwrap();
    file.read_exact(&mut buf[2]).unwrap();
}

fn fill_buffer3_128_with_mr_extend_tdvf(
    buf: &mut [[u8; MRTD_EXTENSION_BUFFER_SIZE]; 3],
    gpa: u64,
    data: &Vec<u8>,
    data_offset: u64,
) {
    buf[0].zeroize();
    buf[1].zeroize();
    buf[2].zeroize();

    // Byte 0 through 8 contain the ASCII string 'MR.EXTEND'.
    // Byte 16 through 23 contain the GPA (in little-endian format).
    // All the other bytes contain 0. The other two extension buffers contain the chunk’s content.
    buf[0][0..MR_EXTEND_ASCII_SIZE].copy_from_slice("MR.EXTEND".as_bytes());
    buf[0][MR_EXTEND_GPA_OFFSET..MR_EXTEND_GPA_OFFSET + MR_EXTEND_GPA_SIZE]
        .copy_from_slice(gpa.to_le_bytes().as_ref());
    buf[1].copy_from_slice(
        &data
            [data_offset as usize..data_offset as usize + (TDH_MR_EXTEND_GRANULARITY as usize / 2)],
    );
    buf[2].copy_from_slice(
        &data[data_offset as usize + (TDH_MR_EXTEND_GRANULARITY as usize / 2)
            ..data_offset as usize + TDH_MR_EXTEND_GRANULARITY as usize],
    );
}
