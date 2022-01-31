## Public key enrollment

This tool accepts **DER encoded** public key file as input and enrolls the **public key hash** into CFV.
Public keys are a SubjectPublicKeyInfo as specified in [IETF RFC 3280](https://datatracker.ietf.org/doc/html/rfc3280).

### Generate public key

1. ECDSA NIST P384

Generate DER encoded public key from DER encoded EC private key file. 
```
openssl ec -inform der -in ecdsa-p384-private.der -pubout -outform der -out ecdsa-p384-public.der
```

2. RSA 3072

Generate DER encoded public key from DER encoded pkcs8 formated private key:
```
openssl rsa -inform der -in rsa-3072-private.pk8 -pubout -outform der -out rsa-3072-public.der
```

### Enrollment

Run the tool:
```
cargo run -- {tdshim_file} {public_key_file} [-H {hash_algorithm}] [-o {output_file}]
```

For example:
```
cargo run -- -H SHA384 -o final.sb.bin ../target/x86_64-unknown-uefi/release/final.bin ecdsa-p384-public.der
```
