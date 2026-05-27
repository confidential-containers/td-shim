# test-td-paging

An integration test crate that exercises the page table functionality from the [`td-paging`](../../td-paging) crate in a bare-metal, `no_std` QEMU VM environment. It uses the [`bootloader`](https://crates.io/crates/bootloader) crate to boot the VM and the `test-runner-client`/`test-runner-server` framework (see [devtools/test-runner-client](../../devtools/test-runner-client)) to collect test results over the serial port.

### What is tested

- `td_paging::init()` — initializes the page table allocator with a given base address and size.
- `setup_paging()` — constructs an `OffsetPageTable` and calls `reserve_page()` to mark the top-level page table as reserved, validating parameter bounds checking.

## How to Run

Tests must be run from the workspace root.
The `test-runner-server` drives QEMU and reports results:

```sh
# Build and run all VM-based paging tests
cargo test -p test-td-paging
```

> **Note:** A working QEMU installation is required.
> The target uses a custom linker script (`x86_64-custom.json`) for bare-metal execution.
