// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(feature = "signer"), no_std)]
use r_efi::efi::Guid;
use scroll::{Pread, Pwrite};

/// GUID for signed payload.
///
/// Please refer to doc/secure_boot.md for definition.
pub const TD_PAYLOAD_SIGN_HEADER_GUID: Guid = Guid::from_fields(
    0xFCF2D558,
    0x9DF5,
    0x4F4D,
    0xB0,
    0xD7,
    &[0x3e, 0x4b, 0x79, 0x8a, 0xb0, 0x66],
); // {FCF2D558-9DF5-4F4D-B0D7-3E4B798AB066}

pub const TD_PAYLOAD_SIGN_ECDSA_NIST_P384_SHA384: u32 = 1;
pub const TD_PAYLOAD_SIGN_RSA_PSS_3072_SHA384: u32 = 2;
pub const TD_PAYLOAD_SIGN_RSA_EXPONENT_SIZE: usize = 8;
pub const TD_PAYLOAD_SIGN_RSA_PUBLIC_KEY_MOD_SIZE: usize = 384;

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

#[cfg(feature = "signer")]
pub mod signer {
    use std::io;
    use std::mem::size_of;
    use std::vec::Vec;

    use log::error;
    use ring::rand;
    use ring::signature::{EcdsaKeyPair, KeyPair, RsaKeyPair, RSA_PSS_SHA384};

    use super::*;

    pub enum SigningAlgorithm {
        Rsapss3072Sha384(RsaKeyPair),
        EcdsaNistP384Sha384(EcdsaKeyPair),
    }

    pub struct PayloadSigner<'a> {
        algorithm: SigningAlgorithm,
        raw_image: &'a [u8],
        signed_image: Vec<u8>,
    }

    impl<'a> PayloadSigner<'a> {
        pub fn new(raw_image: &'a [u8], algorithm: SigningAlgorithm) -> Self {
            PayloadSigner {
                raw_image,
                algorithm,
                signed_image: Vec::new(),
            }
        }

        pub fn sign(&mut self, header: PayloadSignHeader) -> io::Result<&[u8]> {
            let rng = rand::SystemRandom::new();

            self.signed_image = header.as_bytes().to_vec();
            self.signed_image.extend_from_slice(self.raw_image);

            match &self.algorithm {
                SigningAlgorithm::Rsapss3072Sha384(rsa_keypair) => {
                    let modulus = rsa_keypair
                        .public_key()
                        .modulus()
                        .big_endian_without_leading_zero();
                    // TODO: figure out the exact upper bound.
                    if rsa_keypair.public_modulus_len() > 4096 {
                        error!(
                            "Invalid RSA public modulus length: {}",
                            rsa_keypair.public_modulus_len()
                        );
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "invalid RSA public modulus length",
                        ));
                    }

                    let exponent = rsa_keypair
                        .public_key()
                        .exponent()
                        .big_endian_without_leading_zero();
                    if exponent.len() > TD_PAYLOAD_SIGN_RSA_EXPONENT_SIZE {
                        error!(
                            "Invalid RSA exponent length: {}, max {}",
                            exponent.len(),
                            TD_PAYLOAD_SIGN_RSA_EXPONENT_SIZE
                        );
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "invalid RSA exponent size",
                        ));
                    }

                    let mut exp_bytes = [0u8; TD_PAYLOAD_SIGN_RSA_EXPONENT_SIZE];
                    exp_bytes[TD_PAYLOAD_SIGN_RSA_EXPONENT_SIZE - exponent.len()..]
                        .copy_from_slice(exponent);

                    let mut signature: Vec<u8> = vec![0; rsa_keypair.public_modulus_len()];
                    rsa_keypair
                        .sign(&RSA_PSS_SHA384, &rng, &self.signed_image, &mut signature)
                        .map_err(|e| {
                            error!("Failed to sign message with RSA: {}", e);
                            io::Error::new(io::ErrorKind::Other, "failed to sign message")
                        })?;

                    self.signed_image.extend_from_slice(&modulus);
                    self.signed_image.extend_from_slice(&exp_bytes);
                    self.signed_image.extend_from_slice(signature.as_slice());
                }
                SigningAlgorithm::EcdsaNistP384Sha384(ecdsa_keypair) => {
                    let public_key = ecdsa_keypair.public_key().as_ref();
                    // 0x4 -- Uncompressed
                    // 0x0 -- Compressed
                    if public_key[0] != 0x4 {
                        error!("Invalid ECDSA data format: {}", public_key[0],);
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Invalid ECDSA data format",
                        ));
                    }

                    let signature = ecdsa_keypair
                        .sign(&rng, self.signed_image.as_slice())
                        .map_err(|e| {
                            error!("Failed to sign message with ECDSA: {}", e);
                            io::Error::new(io::ErrorKind::Other, "failed to sign message")
                        })?;

                    self.signed_image.extend_from_slice(&public_key[1..]);
                    self.signed_image.extend_from_slice(signature.as_ref());
                }
            }

            Ok(self.signed_image.as_slice())
        }

        pub fn build_header(&self, payload_version: u64, payload_svn: u64) -> PayloadSignHeader {
            let signing_algorithm = match self.algorithm {
                SigningAlgorithm::EcdsaNistP384Sha384(_) => 1,
                SigningAlgorithm::Rsapss3072Sha384(_) => 2,
            };
            let length = (self.raw_image.len() + size_of::<PayloadSignHeader>()) as u32;

            PayloadSignHeader {
                type_guid: *TD_PAYLOAD_SIGN_HEADER_GUID.as_bytes(),
                struct_version: 0x1,
                length,
                payload_version,
                payload_svn,
                signing_algorithm,
                reserved: 0,
            }
        }
    }
}
