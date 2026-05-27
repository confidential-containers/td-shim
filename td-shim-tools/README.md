# td-shim-tools

Host-side tools for the full [td-shim](../td-shim) firmware build pipeline used in Intel TDX confidential VMs, covering build, signing, and inspection operations: linking binary components, generating and patching metadata, signing payloads for secure boot, enrolling keys, and computing TEE measurement reference values. These tools run on the host and are not part of the shim itself.

## Tools

| Binary | Feature flag | Description |
|--------|-------------|-------------|
| `td-shim-ld` | `linker` | Link reset vector, IPL, and optional payload into a TD-Shim firmware image (TDVF or IGVM format) |
| `td-shim-enroll` | `enroller` | Enroll public keys and firmware files into the Configuration Firmware Volume (CFV) for secure boot |
| `td-shim-sign-payload` | `signer` | Sign a td-payload binary with an ECDSA-P384 or RSA-3072 private key |
| `td-shim-checker` | `loader` | Validate a TD-Shim binary and dump its Intel TDX metadata sections |
| `td-shim-info` | `info` | Print TDX_METADATA, TD_INFO, and TD_PARAMS fields from a firmware image |
| `td-shim-strip-info` | *(default)* | Strip reproducibility-breaking fields (timestamps, GUIDs, image base) from a PE binary |
| `td-shim-tee-info-hash` | `tee` | Compute a TEE info hash (SHA-384) from a JSON TD manifest and a TD-Shim image |
| `td-payload-reference-calculator` | `calculator` | Calculate SHA-384 reference values for a kernel image and command-line parameters |
| `td-shim-image-layout-gen` | `layout-gen` | Generate an image layout JSON from measured artifact sizes, for use by `td-shim-ld` |
| `td-shim-metadata-gen` | `metadata-gen` | Generate an Intel TDX metadata JSON from an image layout JSON, for use by `td-shim-ld --metadata` |
| `td-shim-patch` | `patcher` | Patch a TD-Shim image in-place: Intel TDX metadata, TD_PARAMS (from JSON), or TD_INFO |

## Usage

Build all tools (default features):

```sh
cargo build --package td-shim-tools
```

Build a specific tool:

```sh
cargo build --package td-shim-tools --bin td-shim-ld
```

### Linking a firmware image

```sh
td-shim-ld <reset_vector.bin> <ipl.bin> \
    --payload <td-payload.bin> \
    --output final.bin \
    --metadata metadata.json
```

Use `--image-format igvm` to produce an IGVM image instead of TDVF.

### Signing a payload

```sh
td-shim-sign-payload <private_key.pk8> <td-payload.bin> \
    --algorithm ECDSA_P384_SHA384
```

Sample keys are available in [`data/sample-keys/`](../data/sample-keys/).

### Enrolling a public key

```sh
td-shim-enroll --input final.bin --output final.sb.bin \
    --key <public_key.der>
```

### Generating image layout and metadata

```sh
# 1. Compute section sizes from built artifacts
td-shim-image-layout-gen \
    --project-root . \
    --template etc/test_layout_template.json \
    --output layout.json

# 2. Generate metadata JSON from the layout
td-shim-metadata-gen --layout layout.json --output metadata.json
```

### Computing TEE info hash

```sh
td-shim-tee-info-hash <manifest.json> <final.bin> --output tee_info_hash.bin
```

### Patching a firmware image

```sh
td-shim-patch tdx-metadata --input final.bin --output patched.bin
td-shim-patch td-params   --input final.bin --params td_params.json --output patched.bin
td-shim-patch td-info     --input final.bin --td-info td_info.bin   --output patched.bin
```

## Configuration samples

The [`etc/`](etc/) directory contains sample JSON configuration files for metadata, layout templates, TD parameters, and NRX image definitions.
