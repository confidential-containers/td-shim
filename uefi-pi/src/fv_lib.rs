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

use r_efi::efi::Guid;
use r_uefi_pi::fv::{
    CommonSectionHeader, FfsFileHeader, FirmwareVolumeHeader, FvFileType, SectionType,
    FVH_SIGNATURE,
};
use scroll::Pread;

fn get_image_from_sections(sections_data: &[u8], section_type: SectionType) -> Option<&[u8]> {
    let sections = Sections::parse(sections_data, 0)?;
    for (section_header, section_data) in sections {
        if section_header.r#type != section_type {
            continue;
        }
        return Some(section_data);
    }
    None
}

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
        if file_header.r#type != fv_file_type {
            continue;
        }
        let section_data = get_image_from_sections(file_data, section_type)?;
        return Some(section_data);
    }
    None
}

pub fn get_file_from_fv(
    fv_data: &[u8],
    fv_file_type: FvFileType,
    file_name: Guid,
) -> Option<&[u8]> {
    let fv_header: FirmwareVolumeHeader = fv_data.pread(0).ok()?;

    assert!(fv_header.signature == FVH_SIGNATURE);

    let files = Files::parse(fv_data, fv_header.header_length as usize)?;

    for (file_header, file_data) in files {
        if file_header.r#type != fv_file_type || &file_header.name != file_name.as_bytes() {
            continue;
        }

        return Some(file_data);
    }
    None
}

struct Sections<'a> {
    offset: usize,
    buffer: &'a [u8],
}

impl<'a> Sections<'a> {
    pub fn parse(sections_buffer: &'a [u8], offset: usize) -> Option<Self> {
        Some(Sections {
            offset,
            buffer: sections_buffer,
        })
    }
}

impl<'a> Iterator for Sections<'a> {
    type Item = (CommonSectionHeader, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        let base_address = self.buffer as *const [u8] as *const u8 as usize;
        // required 4 bytes alignment
        let offset = ((self.offset + 3 + base_address) & (core::usize::MAX - 3)) - base_address;

        let header_size = core::mem::size_of::<CommonSectionHeader>();
        if offset > self.buffer.len().checked_sub(header_size)? {
            return None;
        }
        let bytes = &self.buffer[offset..];
        let header: CommonSectionHeader = bytes.pread(0).ok()?;
        let section_size = header.size[0] as usize
            + ((header.size[1] as usize) << 8)
            + ((header.size[2] as usize) << 16);

        section_size.checked_sub(header_size)?;
        bytes.len().checked_sub(section_size)?;

        self.offset += section_size;

        Some((header, &bytes[header_size..section_size]))
    }
}

struct Files<'a> {
    offset: usize,
    buffer: &'a [u8],
}

impl<'a> Files<'a> {
    // fv_buffer: fv volume buffer
    // offset: fv volume header_length
    pub fn parse(fv_buffer: &'a [u8], offset: usize) -> Option<Self> {
        Some(Files {
            offset,
            buffer: fv_buffer,
        })
    }
}

impl<'a> Iterator for Files<'a> {
    type Item = (FfsFileHeader, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        let base_address = self.buffer as *const [u8] as *const u8 as usize;
        // required 8 bytes alignment
        let offset = ((self.offset + 7 + base_address) & (core::usize::MAX - 7)) - base_address;

        let header_size = core::mem::size_of::<FfsFileHeader>();
        if offset > self.buffer.len() {
            return None;
        }

        let buffer = &self.buffer[offset..];
        let header: FfsFileHeader = buffer.pread(0).ok()?;

        let data_size = header.size[0] as usize
            + ((header.size[1] as usize) << 8)
            + ((header.size[2] as usize) << 16);

        buffer.len().checked_sub(data_size)?;
        data_size.checked_sub(header_size)?;

        self.offset = offset;
        self.offset += data_size;

        Some((header, &buffer[header_size..data_size]))
    }
}
