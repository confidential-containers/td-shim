## td-shim-layout-builder tool

This tool is for td-payload and td-shim to generate runtime layout config(td-layout/src/runtime.rs).

### How to build

Build `cargo build -p td-shim-tools`

### How to use

- Help 
  ```
  ./target/debug/td-shim-layout-builder -h
  ```

- Generate memory layout source file from default `td-shim-tools/src/bin/td-shim-layout-builder/memory.json` file
  ```
  ./target/debug/td-shim-layout-builder -p -t memory td-shim-tools/src/bin/td-shim-layout-builder/memory.json
  ```

- Generate image layout source file from default `td-shim-tools/src/bin/td-shim-layout-builder/image.json` file
  ```
  ./target/debug/td-shim-layout-builder -p -t image td-shim-tools/src/bin/td-shim-layout-builder/image.json
  ```