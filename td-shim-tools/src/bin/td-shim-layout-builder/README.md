## td-shim-layout-builder tool

This tool is for td-payload and td-shim to generate runtime layout config(td-layout/src/runtime.rs).

### How to build

Build `cargo build -p td-shim-tools`

### How to use

- Help 
  ```
  ./target/debug/td-shim-layout-builder -h
  ```

- Generate runtime.rs from default `devtools/td-layout-config/config.json` file
  ```
  ./target/debug/td-shim-layout-builder -p devtools/td-layout-config/config.json
  ```

- Generate runtime.rs from `json` file
  ```
  ./target/debug/td-shim-layout-builder -p -t json td-shim-tools/src/bin/td-shim-layout-builder/runtime.json
  ```