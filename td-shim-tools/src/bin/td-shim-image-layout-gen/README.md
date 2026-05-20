# td-shim-image-layout-gen

## Overview

Computes a td-shim image layout from built artifacts and a JSON layout template.

This tool measures the actual sizes of payload, IPL (td-shim ELF), and reset
vector binaries, accounts for firmware volume (FV) header overhead, 4 KiB-aligns
all sections, and produces a generated layout JSON.

## Usage

```
td-shim-image-layout-gen --project-root <path> --payload-binary <name> [OPTIONS]
```

### Required Arguments

| Argument | Description |
|----------|-------------|
| `--project-root <path>` | Root directory of the project |
| `--payload-binary <name>` | Payload binary name (filename in target dir) |

### Optional Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--cargo-target-dir <dir>` | `target/` | Cargo target directory |
| `--build-target <target>` | `x86_64-unknown-none` | Build target triple |
| `--cargo-build-directory <dir>` | `release` | Build profile directory |
| `--ipl-binary <name>` | `td-shim` | IPL binary name |
| `--reset-vector-binary <name>` | `ResetVector.bin` | Reset vector binary name |
| `--template <path>` | built-in default | Layout template JSON |
| `--output <path>` | `target/config/image_layout.generated.json` | Output file path |

## Template Format

The layout template JSON defines section sizes in hex:

```json
{
    "TdParams": "0x1000",
    "TempStack": "0x20000",
    "TempHeap": "0x20000",
    "Payload": "0x140000",
    "TdInfo": "0x1000",
    "Metadata": "0x1000",
    "Ipl": "0x2e000",
    "ResetVector": "0x8000"
}
```

Optional fields: `Config`, `Mailbox`, `TdInfo`, `TdParams`, `ImageSize`.

> `ImageSize` is computed automatically from the sum of all sections. If
> provided in the template, it acts as a minimum size (preserving padding).

## How It Works

1. Reads the layout template (or uses built-in defaults).
2. Locates built artifacts under `<target-dir>/<build-target>/<profile>/`.
3. Measures payload binary size, adds FV header overhead (~256 bytes).
4. Measures IPL binary size (max of file size and ELF vaddr extent), adds header overhead (~256 bytes).
5. Measures reset vector binary size.
6. Aligns all sizes to 4 KiB boundaries.
7. Computes total image size.
8. Writes `image_layout.generated.json` to `<project-root>/target/config/`.

## Example

```bash
# After building td-shim and payload:
cargo run --bin td-shim-image-layout-gen -- \
    --project-root . \
    --payload-binary td-payload \
    --template td-shim-tools/etc/test_layout_template.json \
    --output target/config/image_layout.generated.json
```
