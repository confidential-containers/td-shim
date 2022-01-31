# Secure boot guide for td-shim
This guide follows (secure boot specification)[secure_boot.md] for td-shim.

## Build td-shim with secure boot feature enabled

```
cargo xbuild -p rust-tdshim --features "secure-boot" --target x86_64-unknown-uefi --release
```

## Build payload

Refer to [README](../README.md), using ELF as example:

```
pushd rust-td-payload
cargo xbuild --target target.json --release
popd
```

## Generate Key

1. ECDSA NIST P384

Run below command to generate a DER encoded PKCS8 formate EC private key file (on Linux):
```
openssl genpkey -algorithm EC \
        -pkeyopt ec_paramgen_curve:P-384 \
        -pkeyopt ec_param_enc:named_curve \
        -outform der -out ecdsa-p384-private.der

openssl pkcs8 -topk8 -nocrypt -inform der -in ecdsa-p384-private.der -outform der -out ecdsa-p384-private.pk8
```

Generate public key file with private key:
```
openssl ec -inform der -in ecdsa-p384-private.der -pubout -outform der -out ecdsa-p384-public.der
```

2. RSA 3072

Run below command to generate a DER encoded PKCS8 formate RSA private key file (on Linux).
```
openssl genpkey -algorithm RSA \
        -pkeyopt rsa_keygen_bits:3072 \
        -pkeyopt rsa_keygen_pubexp:65537 | \
        openssl pkcs8 -topk8 -nocrypt -outform der > rsa-3072-private.pk8
```

Generate public key file with private key:
```
openssl rsa -inform der -in rsa-3072-private.pk8 -pubout -outform der -out rsa-3072-public.der
```

## Sign payload with [rust-tdpayload-signing](../rust-tdpayload-signing)
Using ECDSA NIST P384 as example:

Clear environment varibles CC and AR at first:
```
set CC=
set AR=
```

Run the signing tool:
```
pushd rust-tdpayload-signing
cargo run -- ../target/target/release/rust-td-payload 1 1 ECDSA_NIST_P384_SHA384 ../sample_key/ecdsa-p384-private.pk8
popd
```
The signed payload file **rust-td-payload-signed** is located in the same folder with input rust-td-payload.

## Enroll public key into CFV with [rust-tdshim-key-enroll](../td-shim-enroll-key)
Build final.bin:
```
cargo run -p rust-td-tool -- target/x86_64-unknown-uefi/release/ResetVector.bin target/x86_64-unknown-uefi/release/rust-tdshim.efi target/target/release/rust-td-payload-signed target/x86_64-unknown-uefi/release/final.bin
```

Enroll public key:
```
pushd rust-tdshim-key-enroll
cargo run -- ../target/x86_64-unknown-uefi/release/final.bin ../sample_key/ecdsa-p384-public.der SHA384
popd
```

The output file **final.sb.bin** with secure boot enabled is located in the same folder with input final.bin.

