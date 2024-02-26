// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::convert::TryInto;
use log::error;
use scroll::Pread;
use td_shim_interface::metadata::{
    self, TdxMetadataDescriptor, TdxMetadataGuid, TdxMetadataSection, TDX_METADATA_DESCRIPTOR_LEN,
    TDX_METADATA_GUID_LEN, TDX_METADATA_OFFSET, TDX_METADATA_SECTION_LEN,
};

pub struct TdShimLoader;

impl TdShimLoader {
    /// generate TdxMetadata elements tupple from input file
    ///
    /// # Arguments
    ///
    /// * `filename` - The td-shim binary which contains TdxMetadata
    pub fn parse(binary_file: Vec<u8>) -> Option<(TdxMetadataDescriptor, Vec<TdxMetadataSection>)> {
        let file_size = binary_file.len();
        // Then read 4 bytes at the pos of [file_len - 0x20]
        // This is the offset of TdxMetadata
        let metadata_offset_addr = file_size - TDX_METADATA_OFFSET as usize;
        let buffer = &binary_file[metadata_offset_addr..metadata_offset_addr + 4];
        let mut metadata_offset = ((buffer[3] as u32) << 24)
            | ((buffer[2] as u32) << 16)
            | ((buffer[1] as u32) << 8)
            | (buffer[0] as u32);
        if metadata_offset > file_size as u32 - TDX_METADATA_OFFSET - TDX_METADATA_DESCRIPTOR_LEN {
            error!("The metadata offset is invalid. {}", metadata_offset);
            error!("{:X?}", buffer);
            return None;
        }

        // Then read the guid
        metadata_offset -= TDX_METADATA_GUID_LEN;
        let buffer = &binary_file
            [metadata_offset as usize..(metadata_offset + TDX_METADATA_GUID_LEN) as usize]
            .try_into()
            .unwrap();
        let metadata_guid = TdxMetadataGuid::from_bytes(buffer);
        if metadata_guid.is_none() {
            error!("Invalid TdxMetadataGuid");
            error!("{:X?}", &buffer);
            return None;
        }

        // Then the descriptor
        metadata_offset += TDX_METADATA_GUID_LEN;
        let buffer = &binary_file
            [metadata_offset as usize..(metadata_offset + TDX_METADATA_DESCRIPTOR_LEN) as usize];
        let metadata_descriptor: TdxMetadataDescriptor =
            buffer.pread::<TdxMetadataDescriptor>(0).unwrap();
        if !metadata_descriptor.is_valid() {
            error!("Invalid TdxMetadata Descriptor: {:?}", metadata_descriptor);
            return None;
        }

        // check if the metadata length exceeds the file size
        let metadata_len = metadata_descriptor.number_of_section_entry * TDX_METADATA_SECTION_LEN
            + TDX_METADATA_GUID_LEN
            + TDX_METADATA_DESCRIPTOR_LEN;
        if metadata_offset + metadata_len + TDX_METADATA_GUID_LEN + TDX_METADATA_DESCRIPTOR_LEN
            > file_size as u32
        {
            error!("Invalid TdxMetadata length {}", metadata_len);
            return None;
        }

        // after that extract the sections one by one
        let mut metadata_sections: Vec<TdxMetadataSection> = Vec::new();
        let mut i = 0;
        metadata_offset += TDX_METADATA_DESCRIPTOR_LEN;

        loop {
            let buffer = &binary_file
                [metadata_offset as usize..(metadata_offset + TDX_METADATA_SECTION_LEN) as usize];

            let section = buffer.pread::<TdxMetadataSection>(0).unwrap();
            metadata_sections.push(section);

            i += 1;
            if i == metadata_descriptor.number_of_section_entry {
                break;
            }
            metadata_offset += TDX_METADATA_SECTION_LEN;
        }

        if i != metadata_descriptor.number_of_section_entry {
            error!("Invalid number of sections.");
            return None;
        }

        // check the validness of the sections
        if metadata::validate_sections(&metadata_sections).is_err() {
            error!("Invalid metadata sections.");
            return None;
        }

        Some((metadata_descriptor, metadata_sections))
    }
}
