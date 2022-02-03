## test_in_no_std

### Organization of `td-shim` Tests

To ease maintenance of test cases for td-shim library crates, test cases are divided into two classes:
- ***unit test cases***: which could/should be run on the host (development machine) directly.
  The standard rust unit test mechanism is used for this type of tests. That is, test cases are implemented within
  the library crate, and `cargo test` is used to run tests.
- ***integration test cases***: which must be run with a special test runner inside dedicated physical/virtual machines.
  Dedicated integration test crates are created under the `tests/` directory to separate them from the library crate,
  so `cargo xtest` and the special test runner `test-runner-server` may be used to run tests.

### Develop Integration Tests

Please follow below steps to develop unit test cases for `#[no_std]` td-shim components. Those components should be
run within a dedicated physical/virtual machines. For convenience, `qemu` is used to create virtual machines for tests.

#### Requirements

You need a nightly [Rust](https://www.rust-lang.org/) compiler with the `llvm-tools-preview` component, which can be
installed through `rustup component add llvm-tools-preview` and `cargo install cargo-xbuild`.

```
rustup install nightly
rustup component add llvm-tools-preview
cargo install cargo-xbuild
```

#### Add integration test skeleton to `main.rs`

```rust
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(test_runner)]
#![reexport_test_harness_main = "test_main"]

#[cfg(test)]
use bootloader::{entry_point, BootInfo};
#[cfg(test)]
entry_point!(kernel_main);

#[cfg(test)]
fn kernel_main(boot_info: &'static mut BootInfo) -> ! {

    // turn the screen gray
    if let Some(framebuffer) = boot_info.framebuffer.as_mut() {
        for byte in framebuffer.buffer_mut() {
            *byte = 0x90;
        }
    }

    #[cfg(test)]
    test_main();

    loop {}
}
```

#### Add dependencies to `Cargo.toml`

```toml
[dependencies]
# add bootloader
bootloader = "0.10.9"

[package.metadata.bootloader]
# To map the complete physical memory starting at virtual address.
map-physical-memory = true
```

#### Write test cases

Note: the test case marker is changed from #[test] to #[test_case]

```rust
#[cfg(test)]
mod tests {
    #[test_case]
    fn trivial_assertion() {
        assert_eq!(1, 1);
    }
}
```

####  Customize cargo configuration for integration tests

Symlink file `devtools/rustc-targets/x86_64-custom.json` into the current rust project, so the project will be compiled
for customized rust target.

Create a `.cargo/config.toml` file in the current rust project with content

```toml
[target.'cfg(target_os = "none")']
runner = "cargo run --package test-runner-server --"

[alias]
ktest = "xtest --target x86_64-custom.json"

```

### Run Integration Tests

####  Manually run integration tests

For example, run the `tests/test-td-payload` integration test

```
cd tests/test-td-payload
cargo ktest
```

##### Run all integration tests

```
make integration-test
```

#### reference

[bootloader](https://github.com/rust-osdev/bootloader)

[examples_test_framework](https://github.com/rust-osdev/bootloader/tree/main/examples/test_framework)
