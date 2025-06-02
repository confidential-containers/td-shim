# IGVM Image

Support for IGVM (Independent Guest Virtual Machine) file format has been added to td-shim (rather than TDVF image). This use case only supports metadata-based image layout, it does not support TD_HOB.

## Build IGVM image

Build TdShim image in native IGVM format.

```
cargo run -p td-layout-config --bin td-layout-config devtools/td-layout-config/config_image.json -t image -m devtools/td-layout-config/config_memory.json -o td-layout/src/build_time.rs

cargo build -p td-shim --target x86_64-unknown-none --release --features=main,tdx

cargo run -p td-shim-tools --bin td-shim-ld --features=linker -- target/x86_64-unknown-none/release/ResetVector.bin target/x86_64-unknown-none/release/td-shim -o target/release/final.igvm --image-format igvm
```

## Firmware relocation

By default, the FW payload is placed at GPA range [4G - fw_size, 4G]. This range is not usable on all VM stacks (e.g. Hyper-V creates GPA memory hole in VMs for range [3.5G, 4G]). The optional command-line argument -m for td-shim-layout-config specifies the metadata config file and loads FW after the PermMem section rather than beneath 4G.

## Reference

* https://crates.io/crates/igvm_defs
* https://github.com/microsoft/igvm