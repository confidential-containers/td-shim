// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use anyhow::*;
use log::debug;
use std::fs;
use std::io::Read;
use std::io::Seek;
use td_shim::metadata::TDX_METADATA_OFFSET;

fn read_from_file(file: &mut std::fs::File, pos: u64, buffer: &mut [u8]) -> Result<()> {
    debug!("Read at pos={0:X}, len={1:X}", pos, buffer.len());
    let _pos = std::io::SeekFrom::Start(pos);
    file.seek(_pos)?;
    file.read_exact(buffer)?;
    debug!("{:X?}", buffer);
    Ok(())
}

pub fn read_from_binary_file(filename: &String) -> Result<Vec<u8>> {
    let f = fs::File::open(filename);
    if f.is_err() {
        bail!("Problem opening the file");
    }

    let mut file = f.unwrap();

    let file_metadata = fs::metadata(filename);
    if file_metadata.is_err() {
        bail!("Problem read file meatadata");
    }

    let file_metadata = file_metadata.unwrap();
    let file_size = file_metadata.len();

    // Then read 4 bytes at the pos of [file_len - 0x20]
    // This is the offset of TdxMetadata
    let mut metadata_buffer: Vec<u8> = vec![0; 4];
    if read_from_file(
        &mut file,
        file_size - TDX_METADATA_OFFSET as u64,
        &mut metadata_buffer,
    )
    .is_err()
    {
        bail!("Failed to read metadata offset");
    }

    // Read whole binary file and return binary string
    let mut buffer: Vec<u8> = vec![0; file_size as usize];
    if read_from_file(&mut file, 0, &mut buffer).is_err() {
        bail!("Failed to read tdshim binary file");
    }
    Ok(buffer)
}
