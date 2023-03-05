## td-shim-layout-builder tool

This tool is for td-payload and td-shim to generate runtime layout config(td-layout/src/runtime.rs).

### How to build

```
pushd devtools/td-layout-config
cargo build
popd
```

### How to use

- Help 
  ```
  ./target/debug/td-layout-config -h
  ```

- Generate memory layout source file for Linux payload from default `devtools/td-layout-config/config_memory_linux.json` file
  ```
  ./target/debug/td-layout-config -t memory devtools/td-layout-config/config_memory_linux.json -o td-layout/src/runtime/linux.rs
  ```

- Generate memory layout source file for executable payload from default `devtools/td-layout-config/config_memory.json` file
  ```
  ./target/debug/td-layout-config -t memory devtools/td-layout-config/config_memory_exec.json -o td-layout/src/runtime/exec.rs
  ```

- Generate image layout source file from default `devtools/td-layout-config/config_image.json` file
  ```
  ./target/debug/td-layout-config -t image devtools/td-layout-config/config_image.json -o td-layout/src/build_time.rs
  ```