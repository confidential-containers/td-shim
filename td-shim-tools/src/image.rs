// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Shared image I/O for td-shim binary patching tools.
//!
//! Provides reading/writing of td-shim firmware images and locating TDX
//! metadata sections within them.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::mem::size_of;
use std::path::Path;

use anyhow::{ensure, Context, Result};
use scroll::Pread;
use td_shim_interface::metadata::{
    TdxMetadataDescriptor, TdxMetadataSection, TDX_METADATA_DESCRIPTOR_LEN, TDX_METADATA_GUID,
    TDX_METADATA_GUID_LEN, TDX_METADATA_OFFSET, TDX_METADATA_SECTION_LEN,
};
use td_shim_interface::td_uefi_pi::pi::guid::Guid;

pub const MAX_IMAGE_SIZE: usize = 0x1000000; // 16 MiB

/// A loaded td-shim firmware image.
pub struct Image {
    pub binary: Vec<u8>,
}

impl Image {
    /// Read a td-shim firmware image from the given path.
    pub fn open(path: &Path) -> Result<Self> {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("failed to stat {}", path.display()))?;
        let size = metadata.len() as usize;
        ensure!(
            size <= MAX_IMAGE_SIZE,
            "image too large ({} bytes, max {})",
            size,
            MAX_IMAGE_SIZE
        );

        let file =
            File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
        let mut reader = BufReader::new(file);
        let mut binary = Vec::with_capacity(size);
        reader
            .read_to_end(&mut binary)
            .with_context(|| format!("failed to read {}", path.display()))?;

        Ok(Image { binary })
    }

    /// Write the image to the given path.
    pub fn write(&self, path: &Path) -> Result<()> {
        let file =
            File::create(path).with_context(|| format!("failed to create {}", path.display()))?;
        let mut writer = BufWriter::new(file);
        writer
            .write_all(&self.binary)
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }
}

/// Parsed TDX metadata from an image.
pub struct ParsedMetadata {
    /// Byte offset of the TdxMetadataDescriptor within the image.
    pub descriptor_offset: usize,
    /// The metadata descriptor.
    pub descriptor: TdxMetadataDescriptor,
    /// The metadata GUID bytes.
    pub guid: [u8; 16],
    /// All sections parsed from the image.
    pub sections: Vec<TdxMetadataSection>,
}

impl ParsedMetadata {
    /// Locate and parse TDX metadata from the image.
    pub fn from_image(image: &Image) -> Result<Self> {
        let eob = image.binary.len();
        ensure!(
            eob > TDX_METADATA_OFFSET as usize + size_of::<u32>(),
            "image too small to contain metadata pointer"
        );

        // Read the metadata offset pointer (located at end - TDX_METADATA_OFFSET)
        let ptr_offset = eob - TDX_METADATA_OFFSET as usize;
        let metadata_offset: u32 = image
            .binary
            .pread_with(ptr_offset, scroll::LE)
            .map_err(|e| anyhow::anyhow!("failed to read metadata offset pointer: {}", e))?;
        let metadata_offset = metadata_offset as usize;

        ensure!(
            metadata_offset + TDX_METADATA_DESCRIPTOR_LEN as usize <= eob,
            "metadata offset 0x{:x} is out of bounds",
            metadata_offset
        );
        ensure!(
            metadata_offset >= TDX_METADATA_GUID_LEN as usize,
            "metadata offset 0x{:x} leaves no room for GUID",
            metadata_offset
        );

        // Read GUID (immediately before the descriptor)
        let guid_start = metadata_offset - TDX_METADATA_GUID_LEN as usize;
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&image.binary[guid_start..metadata_offset]);

        // Validate GUID
        let parsed_guid = Guid::from_bytes(&guid);
        ensure!(
            parsed_guid == TDX_METADATA_GUID,
            "TDX metadata GUID mismatch: expected {:?}, got {:?}",
            TDX_METADATA_GUID,
            parsed_guid
        );

        // Read descriptor
        let descriptor: TdxMetadataDescriptor = image
            .binary
            .pread_with(metadata_offset, scroll::LE)
            .map_err(|e| anyhow::anyhow!("failed to read TDX metadata descriptor: {}", e))?;

        ensure!(
            descriptor.version == 1,
            "unsupported TDX metadata version: {} (expected 1)",
            descriptor.version
        );

        // Read sections
        let num_sections = descriptor.number_of_section_entry as usize;
        let sections_start = metadata_offset + TDX_METADATA_DESCRIPTOR_LEN as usize;
        let sections_end = sections_start + num_sections * TDX_METADATA_SECTION_LEN as usize;
        ensure!(
            sections_end <= eob,
            "metadata sections extend beyond image bounds"
        );

        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let off = sections_start + i * TDX_METADATA_SECTION_LEN as usize;
            let section: TdxMetadataSection = image
                .binary
                .pread_with(off, scroll::LE)
                .map_err(|e| anyhow::anyhow!("failed to read metadata section {}: {}", i, e))?;
            sections.push(section);
        }

        Ok(ParsedMetadata {
            descriptor_offset: metadata_offset,
            descriptor,
            guid,
            sections,
        })
    }

    /// Find a section by type. Returns the first match.
    pub fn find_section(&self, section_type: u32) -> Option<&TdxMetadataSection> {
        self.sections.iter().find(|s| s.r#type == section_type)
    }
}
