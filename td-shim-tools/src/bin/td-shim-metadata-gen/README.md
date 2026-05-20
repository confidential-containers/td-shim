# td-shim-metadata-gen

## Overview

Generates a TDX metadata JSON file consumable by `td-shim-ld --metadata`.

This tool accepts a section configuration file (JSON) that specifies each
metadata section's type, sizes, offsets, and attributes. It validates the
section types and writes the output JSON.

## Usage

```
td-shim-metadata-gen --config <path> --out <path>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `--config <path>` | Input section configuration JSON (required) |
| `--out <path>` | Output metadata JSON file path (required) |

## Configuration Format

The input JSON must have the following structure:

```json
{
    "Sections": [
        {
            "Type": "BFV",
            "Attributes": "0x1",
            "DataOffset": "0x82000",
            "RawDataSize": "0xF7E000",
            "MemoryAddress": "0xFF082000",
            "MemoryDataSize": "0xF7E000"
        }
    ]
}
```

### Valid Section Types

`BFV`, `CFV`, `TD_HOB`, `TempMem`, `PermMem`, `Payload`, `PayloadParam`, `TdInfo`, `TdParams`

## Example

```bash
cargo run --bin td-shim-metadata-gen -- \
    --config td-shim-tools/etc/sample_metadata.json \
    --out target/metadata.json
```

## Output

The output JSON has the same structure as the input and can be passed directly
to `td-shim-ld --metadata`.
