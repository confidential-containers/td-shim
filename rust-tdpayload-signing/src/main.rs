// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]
mod signer;

use ring::signature::{EcdsaKeyPair, RsaKeyPair, ECDSA_P384_SHA384_FIXED_SIGNING};
use signer::*;
use std::vec::Vec;
use std::{env, fs, io::Write, path::Path};

const SIGNED_TDPAYLOAD_NAME: &str = "rust-td-payload-signed";

fn main() {
    let args: Vec<String> = env::args().collect();

    let path_payload = &args[1];
    let version = u64::from_str_radix(&args[2], 10).unwrap();
    let svn = u64::from_str_radix(&args[3], 10).unwrap();
    let algorithm = &args[4];
    let path_private = &args[5];

    println!(
        "\nrust-tdpayload-signing {} {} {} {} {}\n",
        path_payload, version, svn, algorithm, path_private
    );

    let payload = fs::read(path_payload).expect("fail to read td payload");
    let mut private = fs::read(path_private).expect("fail to read private key file");

    let algorithm = match algorithm.as_str() {
        "RSAPSS_3072_SHA384" => {
            let rsa_key_pair = RsaKeyPair::from_pkcs8(&private).unwrap();
            SigningAlgorithm::Rsapss3072Sha384(rsa_key_pair)
        }
        "ECDSA_NIST_P384_SHA384" => {
            let ecdsa_key_pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &private).unwrap();
            SigningAlgorithm::EcdsaNistP384Sha384(ecdsa_key_pair)
        }
        _ => {
            panic!("Unsupported signing algorithm")
        }
    };

    // 1) Generate the verify header and write into the start of signed image
    // 2) Sign the data(verify header | payload binary)
    // 3) Put the public key bytes and signature at the end of the signed imgae.
    let mut signer = PayloadSigner::new(&payload, algorithm);
    let header = signer.build_header(version, svn);
    let signed_image = signer.sign(header);

    // Clear the private key memory.
    private.clear();

    // Create and write the signed payload image.
    let output = Path::new(path_payload)
        .parent()
        .unwrap()
        .join(SIGNED_TDPAYLOAD_NAME);
    let mut signed_image_file = fs::File::create(output).expect("fail to create signed payload");
    signed_image_file.write_all(signed_image).unwrap();
    signed_image_file.sync_data().unwrap();
}
