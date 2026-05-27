# td-shim-interface Fuzz Tests

This directory contains fuzz tests for the `td-shim-interface` crate, targeting the UEFI PI data structure parsers used by the TD-Shim firmware interface.

## Fuzz Targets

| Target | Description |
|--------|-------------|
| `hob_parser` | Fuzzes HOB (Hand-Off Block) list parsing — calls `hob::check_hob_integrity` and various HOB query functions on arbitrary input |
| `payload_parser` | Fuzzes Firmware Volume payload parsing — calls `fv::get_image_from_fv` to extract a PE32 section from arbitrary FV data |
| `cfv_parser` | Fuzzes Configuration Firmware Volume parsing — calls `fv::get_file_from_fv` to locate the secure boot trust anchor file |

AFL variants (`afl_hob_parser`, `afl_payload_parser`, `afl_cfv_parser`) provide the same coverage using [AFL](https://github.com/rust-fuzz/afl.rs) instead of libFuzzer.
They also support replaying a seed file or directory from the command line without the `fuzz` feature enabled.

## Running Fuzz Tests

Requires the `cargo-fuzz` subcommand and a nightly toolchain.

```sh
# Install cargo-fuzz if needed
cargo install cargo-fuzz

# Run a libFuzzer target (from the workspace root or td-shim-interface/)
cargo fuzz run hob_parser
cargo fuzz run payload_parser
cargo fuzz run cfv_parser
```

To run with a specific seed corpus:

```sh
cargo fuzz run hob_parser fuzz/seeds/
```

### AFL targets

Build and run with the `fuzz` feature to enable AFL mode:

```sh
cargo afl build --features fuzz --bin afl_hob_parser
cargo afl fuzz -i fuzz/seeds/ -o out/ target/debug/afl_hob_parser
```

To replay a crash file without AFL:

```sh
cargo run --bin afl_hob_parser -- path/to/crash/file
```
