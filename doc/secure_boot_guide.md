# Secure boot guide for td-shim

This guide follows the [Secure Boot Specification](secure_boot.md) for td-shim.

## Build td-shim with secure boot feature enabled

```
cargo build -p td-shim --target x86_64-unknown-none --release --features=main,tdx,secure-boot
```

## Build payload

Refer to [README](../README.md), using ELF as example:

```
cargo build -p td-payload --target x86_64-unknown-none --release --bin example --features=tdx,start,cet-shstk,stack-guard
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

## Sign payload with [rust-tdpayload-signing](../td-shim-sign-payload)
Using ECDSA NIST P384 as example:

Set environment varibles CC and AR:
```
set CC=clang
set AR=llvm-ar
```

Run the signing tool:
```
cargo run -p td-shim-tools --bin td-shim-sign-payload -- -A ECDSA_NIST_P384_SHA384 data/sample-keys/ecdsa-p384-private.pk8 target/x86_64-unknown-none/release/test 1 1 
```
The signed payload file **td-payload-signed** is located in the same folder with input `test`.

## Enroll public key into CFV with [rust-tdshim-key-enroll](../td-shim-tools)
Build final.bin:
```
cargo run -p td-shim-tools --bin td-shim-ld -- target/x86_64-unknown-none/release/ResetVector.bin target/x86_64-unknown-none/release/td-shim -p target/x86_64-unknown-none/release/td-payload-signed -o target/release/final.bin
```

Enroll public key:
```
cargo run -p td-shim-tools --bin td-shim-enroll -- target/release/final.bin -H SHA384 -k data/sample-keys/ecdsa-p384-public.der
```

The output file **final.sb.bin** with secure boot enabled is located in the same folder with input final.bin.

