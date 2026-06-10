# td-shim-patch

Unified patching tool for td-shim firmware images. Allows replacing any member
of the TDX Metadata descriptor (signature, section attributes), TD Params
structure (all fields of the 1024-byte binary layout), and TD Info section
(GUID, version, SVN, and the opaque payload-specific blob) in a built firmware
image without rebuilding from source.

## Usage

```
td-shim-patch <subcommand> [options]
```

## Subcommands

### `tdx-metadata`

Patches the TDX metadata signature and zeros all section attributes.

```
td-shim-patch tdx-metadata --in <image> --out <image> --signature <hex>
```

| Option | Description |
|--------|-------------|
| `--in <path>` | Input firmware image |
| `--out <path>` | Output firmware image |
| `--signature <hex>` | New metadata signature (e.g., `0x58524e5f`) |

### `td-params`

Patches the TD_PARAMS section from a JSON file.

```
td-shim-patch td-params --in <image> --out <image> --tdparams <json>
```

| Option | Description |
|--------|-------------|
| `--in <path>` | Input firmware image |
| `--out <path>` | Output firmware image |
| `--tdparams <path>` | JSON file with TD_PARAMS fields |

### `td-info`

Patches the TD_INFO section with a generic header and a payload-specific binary blob.

```
td-shim-patch td-info --in <image> --out <image> (--guid <guid> | --raw-guid <guid>) --version <a.b.c> --svn <n> --payload-info <path>
```

| Option | Description |
|--------|-------------|
| `--in <path>` | Input firmware image |
| `--out <path>` | Output firmware image |
| `--guid <guid>` | TD type GUID in UEFI mixed-endian form (e.g., `F9168C5E-CEB2-4FAA-B6BF-329BF39FA1E4`) |
| `--raw-guid <guid>` | TD type GUID as a raw byte sequence with no endian swap (e.g., `01234567-89AB-CDEF-FEDC-BA9876543210`) |
| `--version <a.b.c>` | Release version as `major.minor.update` |
| `--svn <n>` | Security Version Number |
| `--payload-info <path>` | Binary blob with TD-type-specific info |

Exactly one of `--guid` or `--raw-guid` must be supplied. Use `--guid` for
identifiers defined per RFC 4122 / UEFI PI (data1–data3 little-endian,
data4–data5 big-endian on the wire). Use `--raw-guid` for identifiers defined
as a raw 16-byte sequence with no endian swap.

## Building

```
cargo build -p td-shim-tools --bin td-shim-patch
```
