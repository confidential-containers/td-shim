extern crate alloc;
use alloc::vec::Vec;
use core::{convert::TryInto, mem::size_of};
use der::{asn1::UIntBytes, Decodable, Encodable, Message};
use r_efi::efi::Guid;
use r_uefi_pi::fv::FV_FILETYPE_RAW;
use scroll::{Pread, Pwrite};

const CFV_FFS_HEADER_TRUST_ANCHOR_GUID: Guid = Guid::from_fields(
    0x77a2742e,
    0x9340,
    0x4ac9,
    0x8f,
    0x85,
    &[0xb7, 0xb9, 0x78, 0x58, 0x0, 0x21],
); // {77A2742E-9340-4AC9-8F85-B7B978580021}

const FS_PUBKEY_HASH_GUID: Guid = Guid::from_fields(
    0xbe8f65a3,
    0xa83b,
    0x415c,
    0xa1,
    0xfb,
    &[0xf7, 0x8e, 0x10, 0x5e, 0x82, 0x4e],
); // {BE8F65A3-A83B-415C-A1FB-F78E105E824E}

use crate::{
    memslice::{self, get_mem_slice, SliceType},
    tcg::TdEventLog,
};
use ring::{
    digest,
    signature::{self, UnparsedPublicKey, VerificationAlgorithm},
};

const ECDSA_NIST_P384_SHA384: u32 = 1;
const RSA_PSS_3072_SHA384: u32 = 2;
const RSA_PUBLIC_KEY_MOD_SIZE: usize = 384;

pub struct PayloadVerifier<'a> {
    header: VerifyHeader,
    image: &'a [u8],
    config: &'a [u8],
    public_key: &'a [u8],
    formated_public_key: Vec<u8>,
    signature: &'a [u8],
    verify_alg: &'static dyn VerificationAlgorithm,
}

#[repr(C)]
#[derive(Debug, Pread, Pwrite)]
struct VerifyHeader {
    pub type_guid: [u8; 16],
    pub struct_version: u32,
    pub length: u32,
    pub payload_version: u64,
    pub payload_svn: u64,
    pub signing_algorithm: u32,
    pub reserved: u32,
}

#[derive(Debug)]
pub enum VerifyErr {
    InvalidPublicKey,
    InvalidSignature,
}

#[derive(Pread, Pwrite)]
struct CfvDataFileHeader {
    pub type_guid: [u8; 16],
    pub struct_version: u32,
    pub length: u32,
    pub hash_algorithm: u64,
    pub reserved: u32,
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

impl<'a> PayloadVerifier<'a> {
    pub fn new(signed_payload: &'a [u8], config: &'a [u8]) -> Option<Self> {
        let mut formated_public_key: Vec<u8> = Vec::new();
        let verify_alg: &'static dyn VerificationAlgorithm;

        let signature;
        let public_key;

        let header = signed_payload.pread::<VerifyHeader>(0).unwrap();
        let mut offset = header.length as usize;

        // The image to be veiried contains verify header and payload ELF/PE image
        let image = &signed_payload[0..offset];

        match header.signing_algorithm {
            ECDSA_NIST_P384_SHA384 => {
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
            RSA_PSS_3072_SHA384 => {
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
                    modulus: UIntBytes::new(modulus).unwrap(),
                    exponents: UIntBytes::new(exp).unwrap(),
                };
                der.encode_to_vec(&mut formated_public_key).unwrap();

                verify_alg = &signature::RSA_PSS_2048_8192_SHA384;
            }
            _ => {
                return None;
            }
        }

        Some(PayloadVerifier {
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

    pub fn get_trust_anchor(cfv: &'a [u8]) -> &'a [u8] {
        uefi_pi::fv_lib::get_file_from_fv(cfv, FV_FILETYPE_RAW, CFV_FFS_HEADER_TRUST_ANCHOR_GUID)
            .unwrap()
    }

    pub fn get_payload_image(signed_payload: &'a [u8]) -> &'a [u8] {
        let header = signed_payload.pread::<VerifyHeader>(0).unwrap();
        &signed_payload[size_of::<VerifyHeader>()..header.length as usize]
    }

    fn verify_signature(&self) -> bool {
        let signature_verifier =
            UnparsedPublicKey::new(self.verify_alg, self.formated_public_key.as_slice());
        if signature_verifier
            .verify(self.image, self.signature)
            .is_ok()
        {
            return true;
        }

        false
    }

    // Calculate the hash of public key read from signed payload, and
    // compare with the one enrolled in the CFV.
    //
    // The contents in CFV are stored as the below layout:
    //      CFV header | FFS header | data file (header | data)
    // The public key hash is stored in the data field.
    //
    fn verify_public_key(&self) -> bool {
        let file = uefi_pi::fv_lib::get_file_from_fv(
            self.config,
            FV_FILETYPE_RAW,
            CFV_FFS_HEADER_TRUST_ANCHOR_GUID,
        )
        .unwrap();
        let mut readlen = 0;
        let header = file.gread::<CfvDataFileHeader>(&mut readlen).unwrap();

        if &header.type_guid != FS_PUBKEY_HASH_GUID.as_bytes() {
            return false;
        }

        let trusted_hash = &file[readlen..header.length as usize];

        let real_hash = digest::digest(&digest::SHA384, self.public_key);
        let real_hash = real_hash.as_ref();

        real_hash == trusted_hash
    }

    pub fn verify(&self) -> Result<(), VerifyErr> {
        if !self.verify_public_key() {
            return Err(VerifyErr::InvalidPublicKey);
        }

        if !self.verify_signature() {
            return Err(VerifyErr::InvalidSignature);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::tcg::TdEventLog;
    use r_uefi_pi::fv::{self, *};
    use rust_td_layout::build_time::*;
    use scroll::Pread;
    use uefi_pi::fv_lib;

    use super::PayloadVerifier;
    use std::vec::Vec;

    #[test]
    fn test() {
        let bin = include_bytes!("../unit-test/input/final.sb.bin");

        let pstart = TD_SHIM_PAYLOAD_OFFSET as usize;
        let pend = pstart + TD_SHIM_PAYLOAD_SIZE as usize;
        let payload_fv = &bin[pstart..pend];

        let mut offset = 0;
        let payload =
            fv_lib::get_image_from_fv(payload_fv, fv::FV_FILETYPE_DXE_CORE, fv::SECTION_PE32)
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
