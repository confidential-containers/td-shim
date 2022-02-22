// Copyright © 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Functions to access UEFI-PI defined `Firmware Volumes`.

use r_efi::efi::Guid;
use scroll::Pread;

use crate::pi::fv::*;

pub fn get_image_from_fv(
    fv_data: &[u8],
    fv_file_type: FvFileType,
    section_type: SectionType,
) -> Option<&[u8]> {
    let fv_header: FirmwareVolumeHeader = fv_data.pread(0).ok()?;
    if fv_header.signature != FVH_SIGNATURE {
        return None;
    }

    let files = Files::parse(fv_data, fv_header.header_length as usize)?;
    for (file_header, file_data) in files {
        if file_header.r#type == fv_file_type {
            return get_image_from_sections(file_data, section_type);
        }
    }

    None
}

pub fn get_file_from_fv(
    fv_data: &[u8],
    fv_file_type: FvFileType,
    file_name: Guid,
) -> Option<&[u8]> {
    let fv_header: FirmwareVolumeHeader = fv_data.pread(0).ok()?;
    if fv_header.signature != FVH_SIGNATURE {
        return None;
    }

    let files = Files::parse(fv_data, fv_header.header_length as usize)?;
    for (file_header, file_data) in files {
        if file_header.r#type == fv_file_type && &file_header.name == file_name.as_bytes() {
            return Some(file_data);
        }
    }

    None
}

fn get_image_from_sections(sections_data: &[u8], section_type: SectionType) -> Option<&[u8]> {
    let sections = Sections::parse(sections_data, 0)?;

    for (section_header, section_data) in sections {
        if section_header.r#type == section_type {
            return Some(section_data);
        }
    }

    None
}

struct Sections<'a> {
    buffer: &'a [u8],
}

impl<'a> Sections<'a> {
    pub fn parse(sections_buffer: &'a [u8], offset: usize) -> Option<Self> {
        Some(Sections {
            buffer: &sections_buffer[offset..],
        })
    }
}

impl<'a> Iterator for Sections<'a> {
    type Item = (CommonSectionHeader, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        const HEADER_SIZE: usize = core::mem::size_of::<CommonSectionHeader>();
        let header: CommonSectionHeader = self.buffer.pread(0).ok()?;
        let section_size = header.size[0] as usize
            + ((header.size[1] as usize) << 8)
            + ((header.size[2] as usize) << 16);
        section_size.checked_sub(HEADER_SIZE)?;
        self.buffer.len().checked_sub(section_size)?;
        let buf = &self.buffer[HEADER_SIZE..section_size];

        // Align to 4 bytes.
        let section_size = (section_size + 3) & !3;
        if section_size < self.buffer.len() {
            self.buffer = &self.buffer[section_size..];
        } else {
            self.buffer = &self.buffer[0..0];
        }

        Some((header, buf))
    }
}

struct Files<'a> {
    buffer: &'a [u8],
}

impl<'a> Files<'a> {
    pub fn parse(fv_buffer: &'a [u8], fv_header_size: usize) -> Option<Self> {
        Some(Files {
            buffer: &fv_buffer[fv_header_size..],
        })
    }
}

impl<'a> Iterator for Files<'a> {
    type Item = (FfsFileHeader, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        const HEADER_SIZE: usize = core::mem::size_of::<FfsFileHeader>();

        let header: FfsFileHeader = self.buffer.pread(0).ok()?;
        let data_size = header.size[0] as usize
            + ((header.size[1] as usize) << 8)
            + ((header.size[2] as usize) << 16);
        data_size.checked_sub(HEADER_SIZE)?;
        self.buffer.len().checked_sub(data_size)?;
        let buf = &self.buffer[HEADER_SIZE..data_size];

        // Align to 8 bytes.
        let data_size = (data_size + 7) & !7;
        if data_size < self.buffer.len() {
            self.buffer = &self.buffer[data_size..];
        } else {
            self.buffer = &self.buffer[0..0];
        }

        Some((header, buf))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const TEST_GUID1: Guid = Guid::from_fields(
        0x77a2742e,
        0x9340,
        0x4ac9,
        0x8f,
        0x85,
        &[0xb7, 0xb9, 0x78, 0x58, 0x0, 0x21],
    ); // {77A2742E-9340-4AC9-8F85-B7B978580021}

    const TEST_GUID2: Guid = Guid::from_fields(
        0x67a2742e,
        0x9340,
        0x4ac9,
        0x8f,
        0x85,
        &[0xb7, 0xb9, 0x78, 0x58, 0x0, 0x21],
    ); // {67A2742E-9340-4AC9-8F85-B7B978580021}

    #[test]
    fn test_get_image_from_fv() {
        let bytes = include_bytes!("../../fuzzing/in/fuzz_fv_parser/fv_buffer");

        let res = get_image_from_fv(bytes, FV_FILETYPE_DXE_CORE, SECTION_PE32);

        assert_ne!(res, None);
    }

    #[test]
    fn test_get_image_from_fv_with_wrong_signature() {
        let bytes = FirmwareVolumeHeader {
            zero_vector: [0; 16],
            file_system_guid: [0; 16],
            fv_length: 0,
            signature: 0x4856465F, // Incorrect signature
            attributes: 0,
            header_length: 0,
            checksum: 0,
            ext_header_offset: 0,
            reserved: 0,
            revision: 0,
        };

        let res = get_image_from_fv(bytes.as_bytes(), FV_FILETYPE_DXE_CORE, SECTION_PE32);

        assert_eq!(res, None);
    }

    #[test]
    fn test_get_image_from_fv_with_wrong_fv_file_type() {
        let bytes = include_bytes!("../../fuzzing/in/fuzz_fv_parser/fv_buffer");

        // Cannot find fv file type FV_FILETYPE_PEI_CORE
        let res = get_image_from_fv(bytes, FV_FILETYPE_PEI_CORE, SECTION_PE32);

        assert_eq!(res, None);
    }

    #[test]
    fn test_get_image_from_fv_with_wrong_section_type() {
        let bytes = include_bytes!("../../fuzzing/in/fuzz_fv_parser/fv_buffer");

        // Cannot find section type SECTION_PIC
        let res = get_image_from_fv(bytes, FV_FILETYPE_DXE_CORE, SECTION_PIC);

        assert_eq!(res, None);
    }

    #[test]
    fn test_get_file_from_fv() {
        let bytes = include_bytes!("../../fuzzing/in/fuzz_cfv_parser/cfv.bin");

        let res = get_file_from_fv(bytes, FV_FILETYPE_RAW, TEST_GUID1);

        assert_ne!(res, None);
    }

    #[test]
    fn test_get_file_from_fv_with_wrong_signature() {
        let bytes = FirmwareVolumeHeader {
            zero_vector: [0; 16],
            file_system_guid: [0; 16],
            fv_length: 0,
            signature: 0x4856465F, // Incorrect signature
            attributes: 0,
            header_length: 0,
            checksum: 0,
            ext_header_offset: 0,
            reserved: 0,
            revision: 0,
        };

        let res = get_file_from_fv(bytes.as_bytes(), FV_FILETYPE_RAW, TEST_GUID1);

        assert_eq!(res, None);
    }

    #[test]
    fn test_get_file_from_fv_with_wrong_guid() {
        let bytes = include_bytes!("../../fuzzing/in/fuzz_cfv_parser/cfv.bin");

        // Cannot find this GUID
        let res = get_file_from_fv(bytes, FV_FILETYPE_RAW, TEST_GUID2);

        assert_eq!(res, None);
    }
}
