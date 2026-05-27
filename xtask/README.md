# xtask

Cargo xtask automation for building TD-Shim images.

## Usage

```
cargo xtask <command> [options]
```

## Commands

### `image`

Builds a complete TD-Shim firmware image by compiling the shim, optionally compiling or packaging a payload, linking the components with `td-shim-ld`, and optionally enrolling keys or files into the Configuration Firmware Volume (CFV).

**Default output:**
- Debug: `target/debug/final.bin`
- Release: `target/release/final.bin`

#### Options

| Flag | Description |
|------|-------------|
| `--release` | Build with optimizations; log level defaults to `off` |
| `--log-level <LEVEL>`, `--ll <LEVEL>` | Log level: `off`, `error`, `warn`, `info`, `debug`, `trace` (default: `debug` for debug builds, `off` for release) |
| `-t`, `--payload-type <TYPE>` | Payload type: `linux` (bzImage/vmlinux, Linux boot protocol) or `executable` (PE/COFF or ELF) |
| `-o`, `--output <PATH>` | Path for the output image file |
| `--features <LIST>` | Comma-separated additional features for the `td-shim` crate (always includes `main,tdx`) |
| `-m`, `--metadata <PATH>` | Custom metadata configuration file (default: `td-shim-tools/etc/metadata.json`) |
| `-l`, `--layout <PATH>` | Custom layout configuration file; overwrites the layout source for the selected payload type |
| `-p`, `--payload <PATH>` | Path to a payload binary to package into the image |
| `--example-payload` | Build and package the built-in example payload (sets payload type to `executable`) |
| `--enroll-file <GUID,PATH>` | Enroll a raw file into the CFV; repeatable |
| `--enroll-key <GUID,PATH>` | Enroll a public key file into the CFV (requires `--enroll-key-hash-alg`) |
| `-H`, `--enroll-key-hash-alg <ALG>` | Hash algorithm for the enrolled public key (required with `--enroll-key`) |

#### Examples

Build a debug image with no payload:
```sh
cargo xtask image
```

Build a release image with a Linux payload:
```sh
cargo xtask image --release -t linux -p /path/to/bzImage
```

Build a release image with the example payload:
```sh
cargo xtask image --release --example-payload
```

Build with a custom layout and enroll a public key:
```sh
cargo xtask image --layout my-layout.json --enroll-key <GUID>,key.der -H SHA384
```
