// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::convert::TryFrom;
use der::{
    self,
    asn1::{Any, BitString, ObjectIdentifier, UIntBytes},
    Decodable, Decoder,
};

// As specified in https://datatracker.ietf.org/doc/html/rfc5480#appendix-A
// id-ecPublicKey OBJECT IDENTIFIER ::= {
//     iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1
// }
pub const ID_EC_PUBKEY_OID: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.2.1");
// secp384r1 OBJECT IDENTIFIER ::= {
//     iso(1) identified-organization(3) certicom(132) curve(0) 34
// }
pub const SECP384R1_OID: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.34");
// rsaEncryption OBJECT IDENTIFIER ::= {
//    iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 1
// }
pub const RSA_PUBKEY_OID: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.1");

pub type Result<T> = core::result::Result<T, der::Error>;

// As specified in rfc3280#section-4.1.1.2
// SubjectPublicKeyInfo  ::=  SEQUENCE  {
//    algorithm            AlgorithmIdentifier,
//    subjectPublicKey     BIT STRING
// }
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AlgorithmIdentifier<'a> {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<Any<'a>>,
}

// As specified in rfc3280#section-4.1.2.7
// AlgorithmIdentifier  ::=  SEQUENCE  {
//    algorithm               OBJECT IDENTIFIER,
//    parameters              ANY DEFINED BY algorithm OPTIONAL
// }
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub subject_public_key: BitString<'a>,
}

impl<'a> Decodable<'a> for AlgorithmIdentifier<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            Ok(Self {
                algorithm: decoder.decode()?,
                parameters: decoder.decode()?,
            })
        })
    }
}

impl<'a> Decodable<'a> for SubjectPublicKeyInfo<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            Ok(Self {
                algorithm: decoder.decode()?,
                subject_public_key: decoder.decode()?,
            })
        })
    }
}

impl<'a> TryFrom<&'a [u8]> for SubjectPublicKeyInfo<'a> {
    type Error = der::Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(Self::from_der(bytes)?)
    }
}

// rfc3279#section-2.3.1 RSA Keys
// The RSA public key is encoded using the ASN.1 type RSAPublicKey:
//
// RSAPublicKey ::= SEQUENCE {
//     modulus            INTEGER,    -- n
//     publicExponent     INTEGER  }  -- e
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RsaPublicKeyInfo<'a> {
    pub modulus: UIntBytes<'a>,
    pub exponents: UIntBytes<'a>,
}

impl<'a> Decodable<'a> for RsaPublicKeyInfo<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            Ok(Self {
                modulus: decoder.decode()?,
                exponents: decoder.decode()?,
            })
        })
    }
}

impl<'a> TryFrom<&'a [u8]> for RsaPublicKeyInfo<'a> {
    type Error = der::Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Ok(Self::from_der(bytes)?)
    }
}
