# td-loader Fuzz Tests

This directory contains fuzz tests for the `td-loader` crate, which handles loading PE and ELF binaries in the TD-Shim firmware.

## Fuzz Targets

| Target | Fuzzer | Description |
|--------|--------|-------------|
| `pe` | libFuzzer | Fuzzes the PE binary loader (`fuzz_pe_loader`) |
| `elf` | libFuzzer | Fuzzes the ELF binary loader (`fuzz_elf_loader`), including relocation, program headers, and init/fini arrays |
| `afl_pe` | AFL | AFL-based fuzzer for the PE binary loader; accepts a seed file or directory path as input |
| `afl_elf` | AFL | AFL-based fuzzer for the ELF binary loader; accepts a seed file or directory path as input |

Shared fuzzing logic lives in `fuzz_targets/fuzzlib.rs`.

## Running Fuzz Tests

### libFuzzer (default)

```sh
cargo fuzz run pe
cargo fuzz run elf
```

Run with a seed corpus directory:

```sh
cargo fuzz run pe seeds/
cargo fuzz run elf seeds/
```

### AFL

Build with the `fuzz` feature enabled:

```sh
cargo afl build --features fuzz --bin afl_pe
cargo afl fuzz -i seeds/ -o out/ target/debug/afl_pe

cargo afl build --features fuzz --bin afl_elf
cargo afl fuzz -i seeds/ -o out/ target/debug/afl_elf
```

To replay a crash file without AFL (for debugging):

```sh
cargo run --bin afl_pe -- <path/to/crash_file>
cargo run --bin afl_elf -- <path/to/crash_file>
```
