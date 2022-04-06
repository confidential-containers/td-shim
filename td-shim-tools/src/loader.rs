use log::debug;
use log::error;
// use std::convert::TryInto;
use std::fs;
// use std::fs::File;
use std::io;
// use std::io;
use std::io::Read;
use std::io::Seek;
use td_layout::metadata::{
    TdxMetadataDescriptor, TdxMetadataGuid, TdxMetadataSection, TDX_METADATA_DESCRIPTOR_LEN,
    TDX_METADATA_GUID_LEN, TDX_METADATA_OFFSET, TDX_METADATA_SECTION_LEN,
};
// use td_uefi_pi::pi::guid::Guid;

// use crate::linker::TdShimLinker;

pub struct TdShimLoader;

fn read_from_file(file: &mut std::fs::File, pos: u64, buffer: &mut [u8]) -> io::Result<()> {
    debug!("Read at pos={0:X}, len={1:X}", pos, buffer.len());
    let _pos = std::io::SeekFrom::Start(pos);
    file.seek(_pos)?;
    file.read_exact(buffer)?;
    debug!("{:X?}", buffer);
    Ok(())
}

impl TdShimLoader {
    /// generate TdxMetadata elements tupple from input file
    ///
    /// # Arguments
    ///
    /// * `filename` - The td-shim binary which contains TdxMetadata
    pub fn parse(filename: &String) -> Option<(TdxMetadataDescriptor, Vec<TdxMetadataSection>)> {
        // first we open the input file and get its size
        let f = fs::File::open(filename);
        if f.is_err() {
            error!("Problem opening the file");
            return None;
        }

        let mut file = f.unwrap();

        let file_metadata = fs::metadata(filename);
        if file_metadata.is_err() {
            error!("Problem read file meatadata");
            return None;
        }

        let file_metadata = file_metadata.unwrap();
        let file_size = file_metadata.len();

        // Then read 4 bytes at the pos of [file_len - 0x20]
        // This is the offset of TdxMetadata
        let mut buffer: [u8; 4] = [0; 4];
        if read_from_file(
            &mut file,
            file_size - TDX_METADATA_OFFSET as u64,
            &mut buffer,
        )
        .is_err()
        {
            error!("Failed to read metadata offset");
            return None;
        }

        let mut metadata_offset = u32::from_le_bytes(buffer);
        if metadata_offset > file_size as u32 - TDX_METADATA_OFFSET - TDX_METADATA_DESCRIPTOR_LEN {
            error!("The metadata offset is invalid. {}", metadata_offset);
            error!("{:X?}", buffer);
            return None;
        }

        // Then read the guid
        metadata_offset -= TDX_METADATA_GUID_LEN;
        let mut buffer: [u8; TDX_METADATA_GUID_LEN as usize] = [0; TDX_METADATA_GUID_LEN as usize];
        if read_from_file(&mut file, metadata_offset as u64, &mut buffer).is_err() {
            error!("Failed to read metadata guid from file");
            return None;
        }
        let metadata_guid = TdxMetadataGuid::from_bytes(&buffer);
        if metadata_guid.is_none() {
            error!("Invalid TdxMetadataGuid");
            error!("{:X?}", &buffer);
            return None;
        }

        // Then the descriptor
        let mut buffer: [u8; TDX_METADATA_DESCRIPTOR_LEN as usize] =
            [0; TDX_METADATA_DESCRIPTOR_LEN as usize];
        metadata_offset += TDX_METADATA_GUID_LEN;
        if read_from_file(&mut file, metadata_offset as u64, &mut buffer).is_err() {
            error!("Failed to read metadata descriptor from file");
            return None;
        }
        let metadata_descriptor = TdxMetadataDescriptor::from_bytes(&buffer);
        if metadata_descriptor.is_none() {
            error!("Invalid TdxMetadataDescriptor");
            return None;
        }
        let metadata_descriptor = metadata_descriptor.unwrap();

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
            let mut buffer: [u8; TDX_METADATA_SECTION_LEN as usize] =
                [0; TDX_METADATA_SECTION_LEN as usize];
            if read_from_file(&mut file, metadata_offset as u64, &mut buffer).is_err() {
                error!("Failed to read section[{}] from file", i);
                return None;
            }

            let section = TdxMetadataSection::from_bytes(&buffer);
            if section.is_some() {
                metadata_sections.push(section.unwrap());
            } else {
                error!("Failed to parse the content of TdxMetadataSection[{}]", i);
                break;
            }

            i += 1;
            if i == metadata_descriptor.number_of_section_entry {
                break;
            }
            metadata_offset += TDX_METADATA_SECTION_LEN;
        }

        if i != metadata_descriptor.number_of_section_entry {
            return None;
        }

        Some((metadata_descriptor, metadata_sections))
    }
}
