## td-shim checker

This tool accepts td-shim file as input and extracts the TdxMetadata with the format of (TdxMetadataDescriptor, Vec\<TdxMetadataSection\>) if the TdxMetadata is valid in the input td-shim file. After that the TdxMetadata is dump out.

### TdxMetadata

Quotation from [TD Shim Metadata](../../../../doc/tdshim_spec.md#td-shim-metadata),

### td-shim checker

Run the tool:
```
cargo run -p td-shim-tools --bin td-shim-checker --no-default-features --features="loader" -- {tdshim_file}
```

For example:
```
cargo run -p td-shim-tools --bin td-shim-checker -- target/x86_64-unknown-uefi/release/final.bin
```
