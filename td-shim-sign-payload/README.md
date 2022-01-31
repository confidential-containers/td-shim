## Payload signing

This tool accepts **DER encoded PKCS8 format** private key file as input. It generates signed payload binary which contains verify header, public key and signature.

### Generate Key

1. ECDSA NIST P384

Run below command to generate a DER encoded PKCS8 formate EC private key file (on Linux).
```
openssl genpkey -algorithm EC \
        -pkeyopt ec_paramgen_curve:P-384 \
        -pkeyopt ec_param_enc:named_curve \
        -outform der -out ecdsa-p384-private.der

openssl pkcs8 -topk8 -nocrypt -inform der -in ecdsa-p384-private.der -outform der -out ecdsa-p384-private.pk8
```

2. RSA 3072

Run below command to generate a DER encoded PKCS8 formate RSA private key file (on Linux).
```
openssl genpkey -algorithm RSA \
        -pkeyopt rsa_keygen_bits:3072 \
        -pkeyopt rsa_keygen_pubexp:65537 | \
        openssl pkcs8 -topk8 -nocrypt -outform der > rsa-3072-private.pk8
```

### Sign
Clear environment varibles CC and AR at first:
```
set CC=
set AR=
```

Then run the tool:
```
cargo run -- {payload_file} {payload_version} {payload_svn} {signing_algorithm} {private_key_file}
```

For example:
```
cargo run -- ../target/target/release/rust-td-payload 1 1 ECDSA_NIST_P384_SHA384 ecdsa-p384-private.pk8
```
