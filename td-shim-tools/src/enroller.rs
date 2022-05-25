// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::convert::TryFrom;
use std::io;
use std::mem::size_of;
use std::path::PathBuf;
use std::vec::Vec;

use log::error;
use ring::digest;
use td_layout::build_time::{TD_SHIM_CONFIG_OFFSET, TD_SHIM_CONFIG_SIZE, TD_SHIM_FIRMWARE_SIZE};
use td_shim::fv::{FvFfsFileHeader, FvHeader};
use td_shim::secure_boot::{
    CfvPubKeyFileHeader, CFV_FFS_HEADER_TRUST_ANCHOR_GUID, CFV_FILE_HEADER_PUBKEY_GUID,
    PUBKEY_FILE_STRUCT_VERSION_V1, PUBKEY_HASH_ALGORITHM_SHA384,
};
use td_uefi_pi::pi::fv::{
    FIRMWARE_FILE_SYSTEM3_GUID, FVH_REVISION, FVH_SIGNATURE, FV_FILETYPE_RAW,
};

use crate::public_key::{
    RsaPublicKeyInfo, SubjectPublicKeyInfo, ID_EC_PUBKEY_OID, RSA_PUBKEY_OID, SECP384R1_OID,
};
use crate::{write_u24, InputData, OutputFile};

//
// FFS File Header offset
//
const FFS_HEADER_HEADER_CHECKSUM_OFFSET: usize = 0x10;
const FFS_HEADER_FILE_CHECKSUM_OFFSET: usize = 0x11;
const FFS_HEADER_FILE_STATE_OFFSET: usize = 0x17;

fn update_checksum(data: &mut [u8]) {
    // Clear header checksum bit to zero
    data[FFS_HEADER_HEADER_CHECKSUM_OFFSET] = 0x0u8;

    let mut sum = 0x0u8;
    for offset in 0..size_of::<FvFfsFileHeader>() {
        if offset == FFS_HEADER_FILE_CHECKSUM_OFFSET || offset == FFS_HEADER_FILE_STATE_OFFSET {
            continue;
        } else {
            sum = sum.wrapping_add(data[offset] as u8);
        }
    }

    data[FFS_HEADER_HEADER_CHECKSUM_OFFSET] = u8::MAX - sum + 1;
}
// Used to construct a firmware file with a ffs header
// and FV_FILETYPE_RAW type
pub struct FirmwareRawFile {
    data: Vec<u8>,
    // Record the real size of data without padding
    real_size: usize,
}

impl FirmwareRawFile {
    pub fn new(name: &[u8; 16]) -> Self {
        let mut data: Vec<u8> = Vec::new();
        let ffs_header = build_cfv_ffs_header(name);
        data.extend_from_slice(ffs_header.as_bytes());

        Self {
            data,
            real_size: size_of::<FvFfsFileHeader>(),
        }
    }

    pub fn append(&mut self, data: &[u8]) {
        // Remove the padding zeros before push the data
        self.data.truncate(self.real_size);
        self.data.extend_from_slice(data);

        self.real_size = self.data.len();

        // padding zero to ensure the file size is align with 8 bytes
        let padding = 8 - (self.data.len() & 0x7);
        for _ in 0..padding {
            self.data.push(0);
        }

        // Update lengh field
        write_u24(self.data.len() as u32, &mut self.data[20..23]);

        // Update Checksum
        update_checksum(&mut self.data);
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.data.as_slice()
    }
}

/// Build a Configure Firmware Volume header for public key hash.
fn build_cfv_header() -> FvHeader {
    let mut cfv_header = FvHeader::default();

    cfv_header
        .fv_header
        .file_system_guid
        .copy_from_slice(FIRMWARE_FILE_SYSTEM3_GUID.as_bytes());
    cfv_header.fv_header.signature = FVH_SIGNATURE;
    cfv_header.fv_header.header_length = size_of::<FvHeader>() as u16;
    cfv_header.fv_header.fv_length = TD_SHIM_CONFIG_SIZE as u64;
    cfv_header.fv_header.revision = FVH_REVISION;
    cfv_header.fv_header.update_checksum();

    cfv_header.fv_block_map[0].num_blocks = (TD_SHIM_CONFIG_SIZE as u32) / 0x1000;
    cfv_header.fv_block_map[0].length = 0x1000;
    cfv_header.fv_ext_header.ext_header_size = 0x14;

    cfv_header
}

/// Build a Configure Firmware Volume Filesystem header for public key hash.
fn build_cfv_ffs_header(name: &[u8; 16]) -> FvFfsFileHeader {
    let mut cfv_ffs_header = FvFfsFileHeader::default();
    cfv_ffs_header.ffs_header.name.copy_from_slice(name);

    cfv_ffs_header.ffs_header.r#type = FV_FILETYPE_RAW;
    cfv_ffs_header.ffs_header.attributes = 0x00;
    write_u24(
        TD_SHIM_CONFIG_SIZE - size_of::<FvHeader>() as u32,
        &mut cfv_ffs_header.ffs_header.size,
    );
    cfv_ffs_header.ffs_header.update_checksum();

    cfv_ffs_header
}

pub fn enroll_files(
    input_file: &str,
    output_file: PathBuf,
    firmware_files: Vec<FirmwareRawFile>,
) -> io::Result<()> {
    let tdshim_bin = InputData::new(
        input_file,
        TD_SHIM_FIRMWARE_SIZE as usize..=TD_SHIM_FIRMWARE_SIZE as usize,
        "shim binary",
    )?;

    // Build the CFV header and write on the top of CFV
    let mut output = OutputFile::new(output_file)?;
    // Write the clean shim binary into the new one
    output.seek_and_write(0, tdshim_bin.as_bytes(), "enrolled shim binary")?;
    let cfv_header = build_cfv_header();
    output.seek_and_write(
        TD_SHIM_CONFIG_OFFSET as u64,
        cfv_header.as_bytes(),
        "firmware volume header",
    )?;

    for f in firmware_files {
        output.write(f.as_bytes(), "firmware file")?;
    }

    output.flush()?;

    Ok(())
}

/// Build a firmware file which contains public key bytes for secure boot.
///
/// Secure boot in td-shim means the td-shim will verify the digital signature of the payload,
/// based upon a trusted anchor. The payload includes the digital signature and the public key.
/// The td-shim includes a trust anchor - hash of public key.
///
/// Please refer to section "Trust Anchor in Td-Shim" in doc/secure_boot.md for definitions.
pub fn create_key_file(key_file: &str, hash_alg: &str) -> io::Result<FirmwareRawFile> {
    let hash_alg = match hash_alg {
        "SHA384" => &digest::SHA384,
        _ => {
            error!("Unsupported hash algorithm {}", hash_alg);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "unsupported hash algorithm",
            ));
        }
    };

    let key_data = InputData::new(key_file, 1..=1024 * 1024, "public key")?;
    let key = SubjectPublicKeyInfo::try_from(key_data.as_bytes()).map_err(|e| {
        error!("Can not load key from file {}: {}", key_file, e);
        io::Error::new(io::ErrorKind::Other, "invalid key data")
    })?;

    let mut public_bytes: Vec<u8> = Vec::new();
    match key.algorithm.algorithm {
        ID_EC_PUBKEY_OID => {
            if let Some(curve) = key.algorithm.parameters {
                if curve.as_bytes() != SECP384R1_OID.as_bytes() {
                    error!("Unsupported Named Curve from file {}", key_file);
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "unsupported Named Curve",
                    ));
                }
                if key.subject_public_key.as_bytes()[0] != 0x04 {
                    error!("Invalid SECP384R1 public key from file {}", key_file);
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Invalid SECP384R1 public key",
                    ));
                }
                public_bytes.extend_from_slice(&key.subject_public_key.as_bytes()[1..]);
            } else {
                error!("Invalid algorithm parameter from file {}", key_file);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Invalid key algorithm parameter",
                ));
            }
        }
        RSA_PUBKEY_OID => {
            let pubkey =
                RsaPublicKeyInfo::try_from(key.subject_public_key.as_bytes()).map_err(|e| {
                    error!("Invalid key from file {}: {}", key_file, e);
                    io::Error::new(io::ErrorKind::Other, "invalid key from file")
                })?;
            public_bytes.extend_from_slice(pubkey.modulus.as_bytes());
            let mut exp_bytes = [0u8; 8];
            if pubkey.exponents.as_bytes().len() > 8 {
                error!("Invalid exponent size from key file {}", key_file);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Invalid exponent size",
                ));
            }
            exp_bytes[8 - pubkey.exponents.as_bytes().len()..]
                .copy_from_slice(pubkey.exponents.as_bytes());
            public_bytes.extend_from_slice(&exp_bytes);
        }
        t => {
            error!("Unsupported key type {} from file {}", t, key_file);
            return Err(io::Error::new(io::ErrorKind::Other, "unsupported key type"));
        }
    }

    // Hash public key
    let hash = digest::digest(hash_alg, public_bytes.as_slice());
    let hash = hash.as_ref();

    // Create a firmware file to hold secure boot contens
    let mut ff = FirmwareRawFile::new(CFV_FFS_HEADER_TRUST_ANCHOR_GUID.as_bytes());
    //Build public key header in CFV
    let pub_key_header = CfvPubKeyFileHeader {
        type_guid: *CFV_FILE_HEADER_PUBKEY_GUID.as_bytes(),
        struct_version: PUBKEY_FILE_STRUCT_VERSION_V1,
        length: (size_of::<CfvPubKeyFileHeader>() + hash.len()) as u32,
        hash_algorithm: PUBKEY_HASH_ALGORITHM_SHA384,
        ..Default::default()
    };
    ff.append(pub_key_header.as_bytes());
    // public key hash value
    ff.append(hash);

    Ok(ff)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use td_uefi_pi::pi::guid;

    #[test]
    fn test_firmware_file() {
        // {214D240F-77A3-441B-9DA8-C588E43192C1}
        let name = guid::Guid::from_str("214D240F-77A3-441B-9DA8-C588E43192C1").unwrap();
        let size: usize = size_of::<FvFfsFileHeader>();

        let mut ff = FirmwareRawFile::new(name.as_bytes());
        assert_eq!(ff.as_bytes().len(), size);

        ff.append("Firmware file test.".as_bytes());
        assert_eq!(ff.as_bytes().len(), size + 24);

        ff.append("\n".as_bytes());
        assert_eq!(ff.as_bytes().len(), size + 24);

        ff.append("Done.".as_bytes());
        assert_eq!(ff.as_bytes().len(), size + 32);
    }
}
