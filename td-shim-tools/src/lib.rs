// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::{fs, io};

use log::error;
use td_layout::build_time::TD_SHIM_FIRMWARE_SIZE;

#[cfg(all(feature = "enroller", not(feature = "no-config")))]
pub mod enroller;
#[cfg(feature = "enroller")]
pub mod public_key;

#[cfg(feature = "linker")]
pub mod linker;
#[cfg(feature = "linker")]
pub mod metadata;

#[cfg(feature = "signer")]
pub mod signer;

#[cfg(feature = "loader")]
pub mod read_file;

#[cfg(feature = "tee")]
pub mod tee_info_hash;

/// Struct to read input data from a file.
pub struct InputData {
    data: Vec<u8>,
}

impl InputData {
    /// Read data from file into the internal buffer.
    pub fn new(name: &str, range: RangeInclusive<usize>, desc: &str) -> io::Result<Self> {
        // Check file size first to avoid allocating too much memory.
        let md = fs::metadata(name).map_err(|e| {
            error!("Can not get metadata of file {}: {}", name, e);
            e
        })?;
        if md.len() > TD_SHIM_FIRMWARE_SIZE as u64 {
            error!(
                "Size of {} file ({}) is invalid, should be in range [{}-{}]",
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

        // IGVM files need not be TD_SHIM_FIRMWARE_SIZE, as an optimization IGVM files deduplicate pages
        if !name.contains(".igvm") {
            let len = data.len();
            if !range.contains(&len) {
                error!(
                    "Size of {} file ({}) is invalid, should be in range [{}-{}]",
                    desc,
                    len,
                    range.start(),
                    range.end()
                );
                return Err(io::Error::new(io::ErrorKind::Other, "invalid file size"));
            }
        }

        Ok(InputData { data })
    }

    /// Clear the internal data buffer.
    pub fn clear(&mut self) {
        self.data.clear()
    }

    /// Get the input data.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Struct to write out built data.
pub struct OutputFile {
    file: File,
    name: PathBuf,
}

impl OutputFile {
    pub fn new<P: AsRef<Path>>(name: P) -> io::Result<Self> {
        let file = File::create(name.as_ref()).map_err(|e| {
            error!(
                "Can not open output file {}: {}",
                name.as_ref().display(),
                e
            );
            e
        })?;

        Ok(Self {
            file,
            name: name.as_ref().to_path_buf(),
        })
    }

    pub fn seek_and_write(&mut self, off: u64, data: &[u8], desc: &str) -> io::Result<()> {
        self.file
            .seek(SeekFrom::Start(off))
            .and(self.file.write_all(data))
            .map_err(|e| {
                error!(
                    "Can not write {} to file {}: {}",
                    desc,
                    self.name.display(),
                    e
                );
                e
            })
    }

    pub fn write(&mut self, data: &[u8], desc: &str) -> io::Result<()> {
        self.file.write_all(data).map_err(|e| {
            error!(
                "Can not write {} to file {}: {}",
                desc,
                self.name.display(),
                e
            );
            e
        })
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }

    pub fn current_pos(&self) -> io::Result<u64> {
        let name = &self.name;
        Ok(self
            .file
            .metadata()
            .map_err(|e| {
                error!("Can not get size of file {:?}", name.as_os_str());
                e
            })?
            .len())
    }
}
