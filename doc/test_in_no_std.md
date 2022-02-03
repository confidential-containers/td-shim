### test_in_no_std

#### Run test in no_std environment

##### Requirements

You need a nightly [Rust](https://www.rust-lang.org/) compiler with the `llvm-tools-preview` component, which can be installed through `rustup component add llvm-tools-preview` and `cargo install cargo-xbuild`.

```
rustup install nightly
rustup component add llvm-tools-preview
cargo install cargo-xbuild
```

#### Main.rs file header added

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

#### Cargo.toml file add dependency

```toml
[dependencies]
# add bootloader
bootloader = "0.10.9"

[package.metadata.bootloader]
# To map the complete physical memory starting at virtual address.
map-physical-memory = true
```

#### Write test case, the test case mark is changed from #[test] to #[test_case]

```rust
#[cfg(test)]
mod tests {
    #[test_case]
    fn trivial_assertion() {
        assert_eq!(1, 1);
    }
}
```

#### Create a .cargo/config.toml file in the current library, add content

```toml
[target.'cfg(target_os = "none")']
runner = "cargo run --package boot --"

[alias]
ktest = "xtest --target x86_64-custom.json"

```

#### case runs in qemu, refer to current member boot

##### run rust-td-payload test

```
cd rust-td-payload
cargo ktest
```

#### reference

[bootloader](https://github.com/rust-osdev/bootloader)

[examples_test_framework](https://github.com/rust-osdev/bootloader/tree/main/examples/test_framework)
