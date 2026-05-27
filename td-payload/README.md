# td-payload

A `no_std` reference TD (Trust Domain) guest payload for use with [td-shim](../td-shim) on Intel TDX hardware platforms. It is launched by `td-shim` and receives a Hand-Off Block (HOB) pointer as its entry argument. The crate provides runtime initialization scaffolding that concrete payloads can build on, as well as an `example` binary that exercises the platform.

## Entry Point

The entry point is `_start(hob: u64, _payload: u64)`, enabled by the `start` feature.
It drives two initialization phases:

1. **`arch::init::pre_init`** — parses the HOB, sets up paging, heap, shared memory, GDT/IDT, and (optionally) stack guard pages and CET.
2. **`arch::init::init`** — completes platform setup and calls the payload's `main()` function.

For `x86_64-unknown-uefi` targets the symbol is also exported as `efi_main`.

## Modules

| Module | Purpose |
|--------|---------|
| `arch` | Architecture-specific init: GDT, IDT, APIC, paging, serial, CET, guard pages |
| `mm` | Memory management: heap, page table frame allocator, shared memory, E820 layout |
| `hob` | Parses and validates the UEFI PI Hand-Off Block passed by TD-Shim |
| `acpi` | Optional ACPI table initialization (`acpi` feature) |
| `console` | Serial-backed `print!` / `println!` macros |

## Features

| Feature | Description |
|---------|-------------|
| `tdx` (default) | Enables Intel TDX TDCALL support, Intel TDX-aware logger and exception handling |
| `start` | Exposes the `_start` entry point and builds the `example` binary |
| `stack-guard` | Adds a guard page below the stack to detect overflows |
| `cet-shstk` / `cet-ibt` | Intel CET shadow-stack and indirect-branch tracking |
| `acpi` | Initializes ACPI tables from the HOB |
| `no-tdvmcall` | Builds without TDVMCALL (for testing without Intel TDX hardware) |
| `no-tdaccept` | Skips TDACCEPT calls |
| `no-shared-mem` | Disables shared (unencrypted) memory allocation |
| `coverage` | Captures LLVM coverage data via `minicov` |
| `benches` | Enables stack-usage benchmarks via `td-benchmark` |

## Example Binary

The `example` binary (`src/bin/example/`) is a minimal payload that:

- Prints the HOB address.
- Calls `TDREPORT` via `tdx-tdcall` and dumps the result (with `tdx` feature).
- Exports coverage data over shared memory when built with `coverage`.
- Demonstrates multi-processor bring-up (`mp` module).

## Build

The workspace builds td-payload as part of the standard TD-Shim build.
To build the `example` binary standalone, targeting bare-metal x86_64:

```sh
cargo build \
  --package td-payload \
  --bin example \
  --features start \
  --target x86_64-unknown-none \
  -Z build-std=core,alloc \
  -Z build-std-features=compiler-builtins-mem
```

A custom linker script and target JSON (see `devtools/rustc-targets/`) may be required for the full TD-Shim integration build.
