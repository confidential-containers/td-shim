## Public key enrollment

This tool accepts **DER encoded** public key file as input and enrolls the **public key hash** into CFV.
Public keys are a SubjectPublicKeyInfo as specified in [IETF RFC 3280](https://datatracker.ietf.org/doc/html/rfc3280).

### Configuration Firmware Volume (CFV)

Quotation from [Intel TDX Virtual Firmware Design Guide](https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-virtual-firmware-design-guide-rev-1.pdf),
section 3.2:
```
TDVF/TD-SHIM may also include a configuration firmware volume (CFV) that is seperated from the boot firmware volume (BFV).
The reason to do so is because the CFV is measured in the `RTMR`, while the BFV is measured in `TDMR`.

Configuration Firmware Volume includes all the provisoned data and this region is read-only. One possible usage is to
provide UEFI Secure Boot Variable content in this region, such as PK, KEK, db, dbx.

The filesystem GUID must be `EFI_SYSTEM_NV_DATA_FV_GUID`, defined in 
[https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Include/Guid/SystemNvDataGuid.h](https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Include/Guid/SystemNvDataGuid.h)
```

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
