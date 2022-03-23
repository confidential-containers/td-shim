// Copyright (c) 2021 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
use std::io;
use std::mem::size_of;
use std::vec::Vec;

use log::error;
use ring::rand;
use ring::signature::{EcdsaKeyPair, KeyPair, RsaKeyPair, RSA_PSS_SHA384};
use td_shim::secure_boot::{
    PayloadSignHeader, PAYLOAD_SIGN_ECDSA_NIST_P384_SHA384, PAYLOAD_SIGN_RSA_EXPONENT_SIZE,
    PAYLOAD_SIGN_RSA_PSS_3072_SHA384, SIGNED_PAYLOAD_FILE_HEADER_GUID,
};

/// Type of public key.
pub enum SigningAlgorithm {
    Rsapss3072Sha384(RsaKeyPair),
    EcdsaNistP384Sha384(EcdsaKeyPair),
}

/// Utility structure to sign shim payload.
///
/// Secure boot in td-shim means the td-shim will verify the digital signature of the payload,
/// based upon a trusted anchor. The payload includes the digital signature and the public key.
/// The td-shim includes a trust anchor - hash of public key.
///
/// Please refer to section "Trust Anchor in Td-Shim" in doc/secure_boot.md for definitions.
pub struct PayloadSigner<'a> {
    algorithm: SigningAlgorithm,
    raw_image: &'a [u8],
    signed_image: Vec<u8>,
}

impl<'a> PayloadSigner<'a> {
    /// Create a new instance of `PayloadSigner`.
    pub fn new(raw_image: &'a [u8], algorithm: SigningAlgorithm) -> Self {
        PayloadSigner {
            raw_image,
            algorithm,
            signed_image: Vec::new(),
        }
    }

    /// Sign the payload with given header.
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
                if rsa_keypair.public_modulus_len() != 384 {
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
                if exponent.len() > PAYLOAD_SIGN_RSA_EXPONENT_SIZE {
                    error!(
                        "Invalid RSA exponent length: {}, max {}",
                        exponent.len(),
                        PAYLOAD_SIGN_RSA_EXPONENT_SIZE
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid RSA exponent size",
                    ));
                }

                let mut exp_bytes = [0u8; PAYLOAD_SIGN_RSA_EXPONENT_SIZE];
                exp_bytes[PAYLOAD_SIGN_RSA_EXPONENT_SIZE - exponent.len()..]
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

    /// Create a `PayloadSignHeader` with given `payload_version` and `payload_svn`.
    pub fn build_header(&self, payload_version: u64, payload_svn: u64) -> PayloadSignHeader {
        let signing_algorithm = match self.algorithm {
            SigningAlgorithm::EcdsaNistP384Sha384(_) => PAYLOAD_SIGN_ECDSA_NIST_P384_SHA384,
            SigningAlgorithm::Rsapss3072Sha384(_) => PAYLOAD_SIGN_RSA_PSS_3072_SHA384,
        };
        let length = (self.raw_image.len() + size_of::<PayloadSignHeader>()) as u32;

        PayloadSignHeader {
            type_guid: *SIGNED_PAYLOAD_FILE_HEADER_GUID.as_bytes(),
            struct_version: 0x1,
            length,
            payload_version,
            payload_svn,
            signing_algorithm,
            reserved: 0,
        }
    }
}
