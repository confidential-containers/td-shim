// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use r_efi::efi::Guid;
use ring::rand;
use ring::signature::{EcdsaKeyPair, KeyPair, RsaKeyPair, RSA_PSS_SHA384};
use scroll::{Pread, Pwrite};
use std::mem::size_of;
use std::vec::Vec;

const VERIFY_HEADER_GUID: Guid = Guid::from_fields(
    0xFCF2D558,
    0x9DF5,
    0x4F4D,
    0xB0,
    0xD7,
    &[0x3e, 0x4b, 0x79, 0x8a, 0xb0, 0x66],
); // {FCF2D558-9DF5-4F4D-B0D7-3E4B798AB066}

const RSA_EXPONENT_SIZE: usize = 8;

#[derive(Pread, Pwrite)]
struct VerifyHeader {
    pub type_guid: [u8; 16],
    pub struct_version: u32,
    pub length: u32,
    pub payload_version: u64,
    pub payload_svn: u64,
    pub signing_algorithm: u32,
    pub reserved: u32,
}

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

    pub fn sign(&mut self, header: Vec<u8>) -> &[u8] {
        self.signed_image.extend_from_slice(header.as_slice());
        self.signed_image.extend_from_slice(self.raw_image);

        let rng = rand::SystemRandom::new();
        match &self.algorithm {
            SigningAlgorithm::Rsapss3072Sha384(rsa_keypair) => {
                let modulus = rsa_keypair
                    .public_key()
                    .modulus()
                    .big_endian_without_leading_zero();

                let exponent = rsa_keypair
                    .public_key()
                    .exponent()
                    .big_endian_without_leading_zero();

                let mut exp_bytes = [0u8; RSA_EXPONENT_SIZE];
                if exponent.len() > RSA_EXPONENT_SIZE {
                    panic!("Invailid exponent size");
                }
                exp_bytes[RSA_EXPONENT_SIZE - exponent.len()..].copy_from_slice(exponent);

                let mut signature: Vec<u8> = vec![0; rsa_keypair.public_modulus_len()];
                rsa_keypair
                    .sign(
                        &RSA_PSS_SHA384,
                        &rng,
                        self.signed_image.as_slice(),
                        signature.as_mut_slice(),
                    )
                    .unwrap();

                self.signed_image.extend_from_slice(&modulus);
                self.signed_image.extend_from_slice(&exp_bytes);
                self.signed_image.extend_from_slice(signature.as_slice());
            }
            SigningAlgorithm::EcdsaNistP384Sha384(ecdsa_keypair) => {
                let signature = ecdsa_keypair
                    .sign(&rng, self.signed_image.as_slice())
                    .unwrap();
                let public_key = ecdsa_keypair.public_key().as_ref();

                // 0x4 -- Uncompressed
                // 0x0 -- Compressed
                if public_key[0] != 0x4 {
                    panic!("Invalid ecdsa public key");
                }

                self.signed_image.extend_from_slice(&public_key[1..]);
                self.signed_image.extend_from_slice(signature.as_ref());
            }
        }

        self.signed_image.as_slice()
    }

    pub fn build_header(&self, payload_version: u64, payload_svn: u64) -> Vec<u8> {
        let signing_algorithm;
        match self.algorithm {
            SigningAlgorithm::EcdsaNistP384Sha384(_) => {
                signing_algorithm = 1;
            }
            SigningAlgorithm::Rsapss3072Sha384(_) => {
                signing_algorithm = 2;
            }
        }
        let length = (self.raw_image.len() + size_of::<VerifyHeader>()) as u32;

        let mut header = vec![0; size_of::<VerifyHeader>()];
        header
            .as_mut_slice()
            .pwrite(
                VerifyHeader {
                    type_guid: *VERIFY_HEADER_GUID.as_bytes(),
                    struct_version: 0x1,
                    length,
                    payload_version,
                    payload_svn,
                    signing_algorithm,
                    reserved: 0,
                },
                0,
            )
            .unwrap();
        header
    }
}
