# IGVM Image

Support for IGVM (Independent Guest Virtual Machine) file format has been added to td-shim (rather than TDVF image). This use case only supports metadata-based image layout, it does not support TD_HOB.

## Build IGVM image

Build TdShim image in native IGVM format.

```
cargo run -p td-layout-config --bin td-layout-config devtools/td-layout-config/config_image.json -t image --fw_top 0x40000000 -o td-layout/src/build_time.rs

cargo build -p td-shim --target x86_64-unknown-none --release --features=main,tdx

cargo run -p td-shim-tools --bin td-shim-ld --features=linker -- target/x86_64-unknown-none/release/ResetVector.bin target/x86_64-unknown-none/release/td-shim -o target/release/final.igvm --image-format igvm
```

## Firmware relocation using --fw_top

By default, the FW payload is placed at GPA range [4G - fw_size, 4G]. This range is not usable on all VM stacks (e.g. Hyper-V creates GPA memory hole in VMs for range [3.5G, 4G]). The command-line argument --fw_top for td-shim-layout-confg specifies the top GPA address where FW will be loaded [fw_top - fw_size, fw_top]

This example from MigTD sets fw_top to 48M (32M runtime memory + 16M FW size):

```
cargo run -p td-layout-config --bin td-layout-config devtools/td-layout-config/config_image.json -t image --fw_top 0x3000000 -o td-layout/src/build_time.rs
```

## Memory layout

* Definitions:
  * fw_top: equal to (fw_base + fw_size), must be under 4G
  * low_top: highest memory below 4G
  * high_top: highest memory above 4G
* Usable runtime memory ranges:
  * [0, fw_top]
  * [fw_top, low_top]
  * [4G, high_top]

## Reference

* https://crates.io/crates/igvm_defs
* https://github.com/microsoft/igvm