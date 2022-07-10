// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![allow(unused)]
use td_shim::secure_boot::{PayloadVerifier, VerifyErr};

pub fn fuzz_secure_boot_payload(buffer: &[u8]) {
    let cfv = include_bytes!("../seeds/secure_boot_cfv/cfv");
    let verifier = PayloadVerifier::new(buffer, cfv);
    let trust_anchor = PayloadVerifier::get_trust_anchor(cfv);
    if verifier.is_ok() && trust_anchor.is_ok() {
        match verifier.as_ref().unwrap().verify() {
            Ok(v) => v,
            Err(e) => println!("{:?}", e),
        };
        let svn = verifier.unwrap().get_payload_svn();
        PayloadVerifier::get_payload_image(buffer);
    } 
    
}

pub fn fuzz_secure_boot_cfv(buffer: &[u8]) {
    let payload = include_bytes!("../seeds/secure_boot_payload/td-payload-signed");
    let verifier = PayloadVerifier::new(payload, buffer);
    let trust_anchor = PayloadVerifier::get_trust_anchor(buffer);
    if verifier.is_ok() && trust_anchor.is_ok() {
        match verifier.as_ref().unwrap().verify() {
            Ok(v) => v,
            Err(e) => println!("{:?}", e),
        };
        let svn = verifier.unwrap().get_payload_svn();
        PayloadVerifier::get_payload_image(payload);
    } 
}
