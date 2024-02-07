# TD Payload Reference Calculator
A simple tool to calculate td-payload's reference value via bzImage, and kernel parameter

## Usage

### Kernel (bzImage)

The test bzImage can be fetched via

```bash
wget https://github.com/Xynnn007/td-payload-reference-provider/raw/main/tests/bzImage
```
Note: The protocol version of bzImage should be 2.06+.

Test with the example bzImage
```
cargo run -p td-shim-tools --bin td-payload-reference-calculator -- kernel -k bzImage -s 0x10000000
```

The `kernel-size` parameter here means `KERNEL_SIZE` defined in guest firmware, s.t. [TD-SHIM](https://github.com/confidential-containers/td-shim)

Will get the result
```
5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa
```

which is from https://github.com/confidential-containers/attestation-service/pull/33/files#diff-1a4e5ad4c3b043c019c00bc3b3072fd6e1e5b03a5ce8c498e1c0acaf697d9d3fR265

When using [TDVF](https://github.com/tianocore/edk2-staging/tree/2024-tdvf-ww01.4/OvmfPkg) + [QEMU](https://github.com/qemu/qemu) Kernel Direct Boot, the kernel eventlog digest will be pre-processed by QEMU Kernel Direct Boot logic. Which is from https://github.com/confidential-containers/td-shim/issues/633

Test with the example bzImage
```
cargo run -p td-shim-tools --bin td-payload-reference-calculator -- kernel -k bzImage -q
```

Will get the result
```
a5e921ae5bde7ab989216da059057741688eae9114b854ce60733824f93ade8a848f19c719f3fdd5c4f0d7178164a5e2
```

### Kernel Parameter

Test
```
cargo run  -p td-shim-tools --bin td-payload-reference-calculator -- param -p "root=/dev/vda1 console=hvc0 rw" -s 0x1000
```

Will get the result
```
64ed1e5a47e8632f80faf428465bd987af3e8e4ceb10a5a9f387b6302e30f4993bded2331f0691c4a38ad34e4cbbc627
```

which is from https://github.com/confidential-containers/attestation-service/pull/33/files#diff-1a4e5ad4c3b043c019c00bc3b3072fd6e1e5b03a5ce8c498e1c0acaf697d9d3fR269
