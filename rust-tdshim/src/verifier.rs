// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

extern crate alloc;

use alloc::vec::Vec;
use core::mem::size_of;
use der::{asn1::UIntBytes, Decodable, Encodable, Message};
use ring::{
    digest,
    signature::{self, UnparsedPublicKey, VerificationAlgorithm},
};
use scroll::{Pread, Pwrite};
use td_shim_enroll_key::{
    CfvPubKeyFileHeader, CFV_FFS_HEADER_TRUST_ANCHOR_GUID, CFV_FILE_HEADER_PUBKEY_GUID,
};
use td_shim_sign_payload::{
    PayloadSignHeader, TD_PAYLOAD_SIGN_ECDSA_NIST_P384_SHA384, TD_PAYLOAD_SIGN_RSA_PSS_3072_SHA384,
};
use uefi_pi::{fv, pi};

#[derive(Debug)]
pub enum VerifyErr {
    InvalidAlgorithm,
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
#[derive(Copy, Clone, Debug, Eq, PartialEq, Message)]
struct RsaPublicKeyDer<'a> {
    pub modulus: UIntBytes<'a>,
    pub exponents: UIntBytes<'a>,
}

pub struct PayloadVerifier<'a> {
    header: PayloadSignHeader,
    config: &'a [u8],
    image: &'a [u8],
    public_key: &'a [u8],
    formated_public_key: Vec<u8>,
    signature: &'a [u8],
    verify_alg: &'static dyn VerificationAlgorithm,
}

impl<'a> PayloadVerifier<'a> {
    pub fn new(signed_payload: &'a [u8], config: &'a [u8]) -> Result<Self, VerifyErr> {
        let header = signed_payload
            .pread::<PayloadSignHeader>(0)
            .map_err(|_e| VerifyErr::InvalidContent)?;
        let mut offset = header.length as usize;
        if offset <= size_of::<PayloadSignHeader>() || offset >= signed_payload.len() {
            return Err(VerifyErr::InvalidContent);
        }

        // The image to be verified contains signing header and payload ELF/PE image
        let image = &signed_payload[0..offset];

        let mut formated_public_key: Vec<u8> = Vec::new();
        let verify_alg: &'static dyn VerificationAlgorithm;
        let signature;
        let public_key;
        match header.signing_algorithm {
            TD_PAYLOAD_SIGN_ECDSA_NIST_P384_SHA384 => {
                if signed_payload.len() < offset + 192 {
                    return Err(VerifyErr::InvalidContent);
                }

                // Public key (X: first 48 bytes, Y: second 48 bytes)
                public_key = &signed_payload[offset..offset + 96];
                offset += 96;

                // Signature: (R: first 48 bytes, S: second 48 byts)
                signature = &signed_payload[offset..offset + 96];

                // Uncompressed public key
                formated_public_key.push(0x04);
                formated_public_key.extend_from_slice(public_key);

                verify_alg = &signature::ECDSA_P384_SHA384_FIXED;
            }
            TD_PAYLOAD_SIGN_RSA_PSS_3072_SHA384 => {
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
                    modulus: UIntBytes::new(modulus).map_err(|_e| VerifyErr::InvalidContent)?,
                    exponents: UIntBytes::new(exp).map_err(|_e| VerifyErr::InvalidContent)?,
                };
                der.encode_to_vec(&mut formated_public_key)
                    .map_err(|_e| VerifyErr::InvalidContent)?;

                verify_alg = &signature::RSA_PSS_2048_8192_SHA384;
            }
            _ => return Err(VerifyErr::InvalidAlgorithm),
        }

        Ok(PayloadVerifier {
            header,
            image,
            config,
            public_key,
            formated_public_key,
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
        let mut offset = header.length as usize;

        if offset <= size_of::<PayloadSignHeader>() || offset >= signed_payload.len() {
            Err(VerifyErr::InvalidContent)
        } else {
            Ok(&signed_payload[size_of::<PayloadSignHeader>()..offset])
        }
    }

    fn verify_signature(&self) -> Result<(), VerifyErr> {
        let signature_verifier =
            UnparsedPublicKey::new(self.verify_alg, self.formated_public_key.as_slice());
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
        if &header.type_guid != CFV_FILE_HEADER_PUBKEY_GUID.as_bytes() {
            return Err(VerifyErr::InvalidPublicKey);
        } else if header.length as usize > file.len() {
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

/*
#[cfg(test)]
mod test {
    use super::*;

    use super::PayloadVerifier;
    use std::vec::Vec;
    use td_layout::build_time::{
        TD_SHIM_CONFIG_OFFSET, TD_SHIM_CONFIG_SIZE, TD_SHIM_PAYLOAD_OFFSET, TD_SHIM_PAYLOAD_SIZE,
    };

    #[test]
    fn test() {
        let bin = include_bytes!("../unit-test/input/final.sb.bin");

        let pstart = TD_SHIM_PAYLOAD_OFFSET as usize;
        let pend = pstart + TD_SHIM_PAYLOAD_SIZE as usize;
        let payload_fv = &bin[pstart..pend];

        let mut offset = 0;
        let payload = fv::get_image_from_fv(
            payload_fv,
            pi::fv::FV_FILETYPE_DXE_CORE,
            pi::fv::SECTION_PE32,
        )
        .unwrap();

        let cstart = TD_SHIM_CONFIG_OFFSET as usize;
        let cend = cstart + TD_SHIM_CONFIG_SIZE as usize;
        let cfv = &bin[cstart..cend];

        let verifier = PayloadVerifier::new(payload, cfv);
        assert!(
            verifier.is_some(),
            "Cannot get verify header from payload binary"
        );
        assert!(
            verifier.unwrap().verify().is_ok(),
            "Payload verification fail"
        );
    }
}
 */
