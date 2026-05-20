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
td-shim-patch td-info --in <image> --out <image> --guid <guid> --version <a.b.c> --svn <n> --payload-info <path>
```

| Option | Description |
|--------|-------------|
| `--in <path>` | Input firmware image |
| `--out <path>` | Output firmware image |
| `--guid <guid>` | TD type GUID (e.g., `6d8415a6-5701-0247-a696-c0420ce3b4e9`) |
| `--version <a.b.c>` | Release version as `major.minor.update` |
| `--svn <n>` | Security Version Number |
| `--payload-info <path>` | Binary blob with TD-type-specific info |

## Building

```
cargo build -p td-shim-tools --bin td-shim-patch
```
