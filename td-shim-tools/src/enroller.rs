// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::cmp::min;
use std::convert::{TryFrom, TryInto};
use std::io;
use std::mem::size_of;
use std::path::PathBuf;
use std::vec::Vec;

use log::error;
use ring::digest;
use td_layout::build_time::{
    TD_SHIM_CONFIG_BASE, TD_SHIM_CONFIG_OFFSET, TD_SHIM_CONFIG_SIZE, TD_SHIM_FIRMWARE_SIZE,
};
use td_shim::fv::{FvFfsFileHeader, FvHeader};
use td_shim::secure_boot::{
    CfvPubKeyFileHeader, CFV_FFS_HEADER_TRUST_ANCHOR_GUID, CFV_FILE_HEADER_PUBKEY_GUID,
    PUBKEY_FILE_STRUCT_VERSION_V1, PUBKEY_HASH_ALGORITHM_SHA384,
};
use td_shim::write_u24;
use td_shim_interface::td_uefi_pi::pi::fv::{
    FIRMWARE_FILE_SYSTEM3_GUID, FVH_REVISION, FVH_SIGNATURE, FV_FILETYPE_RAW,
};

use crate::public_key::{
    RsaPublicKeyInfo, SubjectPublicKeyInfo, ID_EC_PUBKEY_OID, RSA_PUBKEY_OID, SECP384R1_OID,
};
use crate::{InputData, OutputFile};

use igvm::{
    IgvmDirectiveHeader, IgvmFile, IgvmInitializationHeader, IgvmPlatformHeader, IgvmRevision,
};
use igvm_defs::{IgvmPlatformType, IGVM_VHS_SUPPORTED_PLATFORM, PAGE_SIZE_4K};

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
        if self.real_size % 8 != 0 {
            let padding = 8 - (self.data.len() & 0x7);
            for _ in 0..padding {
                self.data.push(0);
            }
        }

        // Update length field
        write_u24(
            self.real_size as u32,
            (&mut self.data[20..23]).try_into().unwrap(),
        );

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

    if input_file.contains(".igvm") {
        let mut directive_headers: Vec<IgvmDirectiveHeader> = Vec::new();
        let mut igvm_data: Vec<u8> = Vec::new();
        let mut page_data;
        let mut platform_header =
            IgvmPlatformHeader::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
                compatibility_mask: 0,
                highest_vtl: 0,
                platform_type: IgvmPlatformType::TDX,
                platform_version: 0,
                shared_gpa_boundary: 0,
            });
        let mut initialization_headers = Vec::new();
        let igvm =
            IgvmFile::new_from_binary(&tdshim_bin.as_bytes(), None).expect("file parse error");
        let mut cfv_data;
        let mut offset: u64 = 0;
        let mut pagedataflags;

        let cfv_header = build_cfv_header();
        cfv_data = cfv_header.as_bytes().to_vec();

        for f in firmware_files {
            cfv_data.extend(f.as_bytes().to_vec());
        }

        // Create new clean igvm file with CFV header and data
        for dir in igvm
            .directives()
            .iter()
            .filter(|x| matches! {x, IgvmDirectiveHeader::PageData { .. }})
        {
            if let IgvmDirectiveHeader::PageData {
                gpa,
                flags,
                data_type,
                compatibility_mask,
                data,
                ..
            } = dir
            {
                pagedataflags = *flags;
                if *gpa >= TD_SHIM_CONFIG_BASE.into()
                    && *gpa < ((TD_SHIM_CONFIG_BASE + TD_SHIM_CONFIG_SIZE).into())
                {
                    let start = (offset * PAGE_SIZE_4K) as usize;
                    let end = min(((offset + 1) * PAGE_SIZE_4K) as usize, cfv_data.len());
                    if cfv_data.len() == 0 {
                        page_data = vec![];
                    } else {
                        if start < end {
                            page_data = cfv_data[start..end].to_vec();
                            if (end - start) < PAGE_SIZE_4K as usize {
                                let paddingbytes = PAGE_SIZE_4K as usize - (end - start);
                                page_data.extend(std::iter::repeat(0).take(paddingbytes));
                            }
                            pagedataflags.set_unmeasured(false);
                        } else {
                            page_data = vec![];
                        }
                    }
                    offset += 1;
                } else {
                    page_data = data.clone();
                }
                directive_headers.push(IgvmDirectiveHeader::PageData {
                    gpa: *gpa,
                    compatibility_mask: *compatibility_mask,
                    flags: pagedataflags,
                    data_type: *data_type,
                    data: page_data.clone(),
                });
            }
        }

        for p in igvm.platforms() {
            let IgvmPlatformHeader::SupportedPlatform(sp) = p;
            if sp.platform_type == IgvmPlatformType::TDX {
                platform_header = igvm::IgvmPlatformHeader::SupportedPlatform(sp.clone());
            }
        }

        for init in igvm.initializations() {
            match init {
                IgvmInitializationHeader::GuestPolicy {
                    policy,
                    compatibility_mask,
                } => {
                    initialization_headers.push(IgvmInitializationHeader::GuestPolicy {
                        policy: *policy,
                        compatibility_mask: *compatibility_mask,
                    });
                }
                _ => {
                    println!("initialization: {init:?}");
                }
            }
        }

        let igvm_enroll = IgvmFile::new(
            IgvmRevision::V1,
            vec![platform_header],
            initialization_headers,
            directive_headers,
        )
        .unwrap();
        igvm_enroll.serialize(&mut igvm_data).unwrap();
        output.seek_and_write(0, igvm_data.as_slice(), "enrolled shim binary")?;
    } else {
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
    }

    output.flush()?;

    Ok(())
}

// Uncompressed ecdsa p384 public key length
const ECDSA_P384_PUB_KEY_LEN: usize = 96;
// Prefix of uncompressed ecdsa public key
const ECDSA_UNCOMPRESSED_PUB_KEY_PREFIX: u8 = 0x04;
// Minimal RSA exponent
const RSA_EXPONENT: u64 = 0x10001;
// RSA 3072 public key modulus length
const RSA_3072_PUB_KEY_MOD_LEN: usize = 384;
// Maximum size of public key file (1024 KiB)
const PUB_KEY_MAX_SIZE: usize = 1024 * 1024;

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

    let key_data = InputData::new(key_file, 1..=PUB_KEY_MAX_SIZE, "public key")?;
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

                // The first byte indicates whether the key is compressed or uncompressed. The
                // uncompressed form is indicated by 0x04 and the compressed form is indicated by
                // either 0x02 or 0x03
                // Here only the uncompressed form is supported and the length should be 96 bytes.
                if key.subject_public_key.as_bytes()[0] != ECDSA_UNCOMPRESSED_PUB_KEY_PREFIX
                    || key.subject_public_key.as_bytes()[1..].len() != ECDSA_P384_PUB_KEY_LEN
                {
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

            let exp = u64::from_be_bytes(exp_bytes);

            // According to FIPS 186-5, RSA exponent should be an odd and in range (2^16, 2^256)
            // As stated in the https://github.com/confidential-containers/td-shim/blob/main/doc/secure_boot.md,
            // use the fixed exponent 0x10001 here.
            if exp != RSA_EXPONENT || pubkey.modulus.as_bytes().len() != RSA_3072_PUB_KEY_MOD_LEN {
                return Err(io::Error::new(io::ErrorKind::Other, "Invalid exponent"));
            }

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
    use td_shim_interface::td_uefi_pi::pi::guid;

    fn read_u24(data: &[u8]) -> u32 {
        let mut num = data[0] as u32;
        num |= (data[1] as u32) << 8;
        num |= (data[2] as u32) << 16;

        num
    }

    #[test]
    fn test_firmware_file() {
        // {214D240F-77A3-441B-9DA8-C588E43192C1}
        let name = guid::Guid::from_str("214D240F-77A3-441B-9DA8-C588E43192C1").unwrap();
        let size: usize = size_of::<FvFfsFileHeader>();

        let mut ff = FirmwareRawFile::new(name.as_bytes());
        assert_eq!(ff.as_bytes().len(), size);

        ff.append("Firmware file test.".as_bytes());
        assert_eq!(read_u24(&ff.as_bytes()[20..23]), size as u32 + 19);
        assert_eq!(ff.as_bytes().len(), size + 24);

        ff.append("\n".as_bytes());
        assert_eq!(read_u24(&ff.as_bytes()[20..23]), size as u32 + 20);
        assert_eq!(ff.as_bytes().len(), size + 24);

        ff.append("Done.".as_bytes());
        assert_eq!(read_u24(&ff.as_bytes()[20..23]), size as u32 + 25);
        assert_eq!(ff.as_bytes().len(), size + 32);
    }
}
