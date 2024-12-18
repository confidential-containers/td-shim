// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Constants and structs to enable secure boot for td-shim.
//!
//! A customized secure boot protocol is designed for td-shim, please refer to `doc/secure_boot.md`
//! for details.

use core::mem::size_of;
use core::ptr::slice_from_raw_parts;

use der::{asn1::UintRef, Encode, Sequence};
use r_efi::efi::Guid;
use ring::{
    digest,
    signature::{self, UnparsedPublicKey, VerificationAlgorithm},
};
use scroll::{Pread, Pwrite};
use td_shim_interface::td_uefi_pi::{fv, pi};

/// GUID for secure boot trust anchor in the Configuration Firmware Volume (CFV).
pub const CFV_FFS_HEADER_TRUST_ANCHOR_GUID: Guid = Guid::from_fields(
    0x77a2742e,
    0x9340,
    0x4ac9,
    0x8f,
    0x85,
    &[0xb7, 0xb9, 0x78, 0x58, 0x0, 0x21],
); // {77A2742E-9340-4AC9-8F85-B7B978580021}

/// GUID for secure boot pubkey hash file in the Configuration Firmware Volume (CFV).
pub const CFV_FILE_HEADER_PUBKEY_GUID: Guid = Guid::from_fields(
    0xbe8f65a3,
    0xa83b,
    0x415c,
    0xa1,
    0xfb,
    &[0xf7, 0x8e, 0x10, 0x5e, 0x82, 0x4e],
); // {BE8F65A3-A83B-415C-A1FB-F78E105E824E}

pub const PUBKEY_FILE_STRUCT_VERSION_V1: u32 = 0x01;
pub const PUBKEY_HASH_ALGORITHM_SHA384: u64 = 1;

const RSA_3072_MAX_DER_PUBLIC_KEY_SIZE: usize = 396;
const ECDSA_3072_PUBLIC_KEY_SIZE: usize = 97;
const FORMATED_PUBKEY_MAX_SIZE: usize = RSA_3072_MAX_DER_PUBLIC_KEY_SIZE;

#[repr(C, align(4))]
#[derive(Debug, Default, Pread, Pwrite)]
pub struct CfvPubKeyFileHeader {
    pub type_guid: [u8; 16],
    pub struct_version: u32,
    pub length: u32,
    pub hash_algorithm: u64,
    pub _reserved: u32,
    pub _pad: u32,
}

impl CfvPubKeyFileHeader {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

/// GUID for signed payload.
pub const SIGNED_PAYLOAD_FILE_HEADER_GUID: Guid = Guid::from_fields(
    0xFCF2D558,
    0x9DF5,
    0x4F4D,
    0xB0,
    0xD7,
    &[0x3e, 0x4b, 0x79, 0x8a, 0xb0, 0x66],
); // {FCF2D558-9DF5-4F4D-B0D7-3E4B798AB066}

pub const PAYLOAD_SIGN_ECDSA_NIST_P384_SHA384: u32 = 1;
pub const PAYLOAD_SIGN_RSA_PSS_3072_SHA384: u32 = 2;
pub const PAYLOAD_SIGN_RSA_EXPONENT_SIZE: usize = 8;
pub const PAYLOAD_SIGN_RSA_PUBLIC_KEY_MOD_SIZE: usize = 384;

/// File header for signed payload.
///
/// Please refer to doc/secure_boot.md for definition.
#[repr(C, align(4))]
#[derive(Debug, Pread, Pwrite)]
pub struct PayloadSignHeader {
    pub type_guid: [u8; 16],
    pub struct_version: u32,
    pub length: u32,
    pub payload_version: u64,
    pub payload_svn: u64,
    pub signing_algorithm: u32,
    pub reserved: u32,
}

impl PayloadSignHeader {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            &*core::ptr::slice_from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}

#[derive(Debug)]
pub enum VerifyErr {
    UnknownAlgorithm,
    InvalidContent,
    InvalidPublicKey,
    InvalidSignature,
}

// rfc3279#section-2.3.1 RSA Keys
// The RSA public key is encoded using the ASN.1 type RSAPublicKey:
//
// RSAPublicKey ::= SEQUENCE {
//     modulus            INTEGER,    -- n
//     publicExponent     INTEGER  }  -- e
//
#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence)]
struct RsaPublicKeyDer<'a> {
    pub modulus: UintRef<'a>,
    pub exponents: UintRef<'a>,
}

pub struct PayloadVerifier<'a> {
    header: PayloadSignHeader,
    config: &'a [u8],
    image: &'a [u8],
    public_key: &'a [u8],
    formated_public_key: [u8; FORMATED_PUBKEY_MAX_SIZE],
    public_key_size: usize,
    signature: &'a [u8],
    verify_alg: &'static dyn VerificationAlgorithm,
}

impl<'a> PayloadVerifier<'a> {
    pub fn new(signed_payload: &'a [u8], config: &'a [u8]) -> Result<Self, VerifyErr> {
        let header = signed_payload
            .pread::<PayloadSignHeader>(0)
            .map_err(|_e| VerifyErr::InvalidContent)?;

        if &header.type_guid != SIGNED_PAYLOAD_FILE_HEADER_GUID.as_bytes() {
            return Err(VerifyErr::InvalidContent);
        }

        let mut offset = header.length as usize;
        if offset <= size_of::<PayloadSignHeader>() || offset >= signed_payload.len() {
            return Err(VerifyErr::InvalidContent);
        }

        // The image to be verified contains signing header and payload ELF/PE image
        let image = &signed_payload[0..offset];

        let mut formated_public_key = [0u8; FORMATED_PUBKEY_MAX_SIZE];
        let public_key_size;
        let verify_alg: &'static dyn VerificationAlgorithm;
        let signature;
        let public_key;
        match header.signing_algorithm {
            PAYLOAD_SIGN_ECDSA_NIST_P384_SHA384 => {
                if signed_payload.len() < offset + 192 {
                    return Err(VerifyErr::InvalidContent);
                }

                // Public key (X: first 48 bytes, Y: second 48 bytes)
                public_key = &signed_payload[offset..offset + 96];
                offset += 96;

                // Signature: (R: first 48 bytes, S: second 48 byts)
                signature = &signed_payload[offset..offset + 96];

                // Uncompressed public key
                formated_public_key[0] = 0x04;
                formated_public_key[1..1 + public_key.len()].copy_from_slice(public_key);
                public_key_size = ECDSA_3072_PUBLIC_KEY_SIZE;

                verify_alg = &signature::ECDSA_P384_SHA384_FIXED;
            }
            PAYLOAD_SIGN_RSA_PSS_3072_SHA384 => {
                if signed_payload.len() < offset + 776 {
                    return Err(VerifyErr::InvalidContent);
                }

                // Store the Mod(384 bytes)||Exponent(8 bytes) to the public_key to verify hash.
                public_key = &signed_payload[offset..offset + 392];

                // Public Mod (384 bytes)
                let modulus = &signed_payload[offset..offset + 384];
                offset += 384;

                // Public Exponent (8 bytes)
                let exp = &signed_payload[offset..offset + 8];
                offset += 8;

                // Signature (384 bytes)
                signature = &signed_payload[offset..offset + 384];

                let der = RsaPublicKeyDer {
                    modulus: UintRef::new(modulus).map_err(|_e| VerifyErr::InvalidContent)?,
                    exponents: UintRef::new(exp).map_err(|_e| VerifyErr::InvalidContent)?,
                };
                let encoded = der
                    .encode_to_slice(&mut formated_public_key)
                    .map_err(|_e| VerifyErr::InvalidContent)?;
                if encoded.len() > RSA_3072_MAX_DER_PUBLIC_KEY_SIZE {
                    return Err(VerifyErr::InvalidPublicKey);
                }
                public_key_size = encoded.len();

                verify_alg = &signature::RSA_PSS_2048_8192_SHA384;
            }
            _ => return Err(VerifyErr::UnknownAlgorithm),
        }

        Ok(PayloadVerifier {
            header,
            image,
            config,
            public_key,
            formated_public_key,
            public_key_size,
            signature,
            verify_alg,
        })
    }

    pub fn get_payload_svn(&self) -> u64 {
        self.header.payload_svn
    }

    pub fn get_trust_anchor(cfv: &'a [u8]) -> Result<&'a [u8], VerifyErr> {
        fv::get_file_from_fv(
            cfv,
            pi::fv::FV_FILETYPE_RAW,
            CFV_FFS_HEADER_TRUST_ANCHOR_GUID,
        )
        .ok_or(VerifyErr::InvalidContent)
    }

    pub fn get_payload_image(signed_payload: &'a [u8]) -> Result<&'a [u8], VerifyErr> {
        let header = signed_payload
            .pread::<PayloadSignHeader>(0)
            .map_err(|_e| VerifyErr::InvalidContent)?;
        let offset = header.length as usize;

        if offset <= size_of::<PayloadSignHeader>() || offset > signed_payload.len() {
            Err(VerifyErr::InvalidContent)
        } else {
            Ok(&signed_payload[size_of::<PayloadSignHeader>()..offset])
        }
    }

    fn verify_signature(&self) -> Result<(), VerifyErr> {
        let signature_verifier = UnparsedPublicKey::new(
            self.verify_alg,
            &self.formated_public_key[..self.public_key_size],
        );
        signature_verifier
            .verify(self.image, self.signature)
            .map_err(|_e| VerifyErr::InvalidSignature)
    }

    // Calculate the hash of public key read from signed payload, and
    // compare with the one enrolled in the CFV.
    //
    // The contents in CFV are stored as the below layout:
    //      CFV header | FFS header | data file (header | data)
    // The public key hash is stored in the data field.
    //
    fn verify_public_key(&self) -> Result<(), VerifyErr> {
        let file = fv::get_file_from_fv(
            self.config,
            pi::fv::FV_FILETYPE_RAW,
            CFV_FFS_HEADER_TRUST_ANCHOR_GUID,
        )
        .ok_or(VerifyErr::InvalidPublicKey)?;

        let mut readlen = 0;
        let header = file.gread::<CfvPubKeyFileHeader>(&mut readlen).unwrap();
        if &header.type_guid != CFV_FILE_HEADER_PUBKEY_GUID.as_bytes()
            || header.length as usize > file.len()
            || readlen > header.length as usize
        {
            return Err(VerifyErr::InvalidPublicKey);
        }

        let trusted_hash = &file[readlen..header.length as usize];
        let real_hash = digest::digest(&digest::SHA384, self.public_key);
        if real_hash.as_ref() != trusted_hash {
            return Err(VerifyErr::InvalidPublicKey);
        }

        Ok(())
    }

    pub fn verify(&self) -> Result<(), VerifyErr> {
        self.verify_public_key()?;
        self.verify_signature()?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_payload_verifier_new() {
        assert!(PayloadVerifier::new(&[], &[]).is_err());

        let mut hdr = PayloadSignHeader {
            type_guid: *SIGNED_PAYLOAD_FILE_HEADER_GUID.as_bytes(),
            struct_version: 1,
            length: 0,
            payload_version: 1,
            payload_svn: 1,
            signing_algorithm: 0,
            reserved: 0,
        };
        assert!(PayloadVerifier::new(hdr.as_bytes(), &[]).is_err());
        hdr.length = size_of::<PayloadSignHeader>() as u32;
        assert!(PayloadVerifier::new(hdr.as_bytes(), &[]).is_err());

        hdr.length = size_of::<PayloadSignHeader>() as u32 + 1;
        let mut buf = [0u8; 2048];
        buf[0..size_of::<PayloadSignHeader>()].copy_from_slice(hdr.as_bytes());
        assert!(PayloadVerifier::new(&buf[0..size_of::<PayloadSignHeader>() + 1], &[]).is_err());

        hdr.signing_algorithm = PAYLOAD_SIGN_RSA_PSS_3072_SHA384;
        buf[0..size_of::<PayloadSignHeader>()].copy_from_slice(hdr.as_bytes());
        assert!(PayloadVerifier::new(&buf[0..size_of::<PayloadSignHeader>() + 1], &[]).is_err());
        assert!(PayloadVerifier::new(&buf[0..size_of::<PayloadSignHeader>() + 777], &[]).is_ok());

        hdr.signing_algorithm = PAYLOAD_SIGN_ECDSA_NIST_P384_SHA384;
        buf[0..size_of::<PayloadSignHeader>()].copy_from_slice(hdr.as_bytes());
        assert!(PayloadVerifier::new(&buf[0..size_of::<PayloadSignHeader>() + 1], &[]).is_err());
        assert!(PayloadVerifier::new(&buf[0..size_of::<PayloadSignHeader>() + 193], &[]).is_ok());
    }

    #[test]
    fn test_get_payload_image() {
        assert!(PayloadVerifier::get_payload_image(&[]).is_err());

        let mut hdr = PayloadSignHeader {
            type_guid: *SIGNED_PAYLOAD_FILE_HEADER_GUID.as_bytes(),
            struct_version: 1,
            length: 0,
            payload_version: 1,
            payload_svn: 1,
            signing_algorithm: 0,
            reserved: 0,
        };
        assert!(PayloadVerifier::get_payload_image(hdr.as_bytes()).is_err());
        hdr.length = size_of::<PayloadSignHeader>() as u32;
        assert!(PayloadVerifier::get_payload_image(hdr.as_bytes()).is_err());

        hdr.length = size_of::<PayloadSignHeader>() as u32 + 1;
        let mut buf = [0u8; 2048];
        buf[0..size_of::<PayloadSignHeader>()].copy_from_slice(hdr.as_bytes());
        assert!(
            PayloadVerifier::get_payload_image(&buf[0..size_of::<PayloadSignHeader>()]).is_err()
        );
        assert_eq!(
            PayloadVerifier::get_payload_image(&buf[0..size_of::<PayloadSignHeader>() + 1])
                .unwrap(),
            &[0u8]
        );
        assert_eq!(
            PayloadVerifier::get_payload_image(&buf[0..size_of::<PayloadSignHeader>() + 2])
                .unwrap(),
            &[0u8]
        );
    }

    #[test]
    fn test_get_trust_anchor() {
        let cfv = include_bytes!("../fuzz/seeds/secure_boot_cfv/cfv");
        let payload = include_bytes!("../fuzz/seeds/secure_boot_payload/td-payload-signed");

        let verifier = PayloadVerifier::new(payload, cfv);
        assert!(
            verifier.is_ok(),
            "Cannot read verify header from payload binary"
        );

        let trust_anchor = PayloadVerifier::get_trust_anchor(cfv);
        assert!(trust_anchor.is_ok(), "Fail to get trust anchor from CFV");
    }

    #[test]
    fn test_get_payload_svn() {
        let cfv = include_bytes!("../fuzz/seeds/secure_boot_cfv/cfv");
        let payload = include_bytes!("../fuzz/seeds/secure_boot_payload/td-payload-signed");

        let verifier = PayloadVerifier::new(payload, cfv);
        assert!(
            verifier.is_ok(),
            "Cannot read verify header from payload binary"
        );
        assert_eq!(verifier.as_ref().unwrap().get_payload_svn(), 1);
    }

    #[test]
    fn test_verifier() {
        let cfv = include_bytes!("../fuzz/seeds/secure_boot_cfv/cfv");
        let payload = include_bytes!("../fuzz/seeds/secure_boot_payload/td-payload-signed");

        let verifier = PayloadVerifier::new(payload, cfv);
        assert!(
            verifier.is_ok(),
            "Cannot read verify header from payload binary"
        );

        assert!(verifier.unwrap().verify().is_ok(), "Verification fails");
    }
}
