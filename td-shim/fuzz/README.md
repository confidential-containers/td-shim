# TD-Shim Fuzz Tests

Fuzz tests for the `td-shim` crate, targeting the secure boot verification logic.
Two fuzzing engines are supported: [libFuzzer](https://llvm.org/docs/LibFuzzer.html) (via `cargo fuzz`) and [AFL](https://github.com/rust-fuzz/afl.rs).

## Fuzz Targets

| Target | Engine | Description |
|---|---|---|
| `secure_boot_payload` | libFuzzer | Fuzzes `PayloadVerifier` with arbitrary payload bytes against a fixed CFV seed. Exercises payload parsing, signature verification, SVN extraction, and image extraction. |
| `secure_boot_cfv` | libFuzzer | Fuzzes `PayloadVerifier` with arbitrary CFV bytes against a fixed signed payload seed. Exercises CFV parsing and trust anchor extraction. |
| `afl_secure_boot_payload` | AFL | AFL equivalent of `secure_boot_payload`. Also accepts a seed file or directory as a command-line argument for replaying crashes. |
| `afl_secure_boot_cfv` | AFL | AFL equivalent of `secure_boot_cfv`. Also accepts a seed file or directory as a command-line argument for replaying crashes. |

Seeds used by the targets are located in `seeds/`.

## Running Fuzz Tests

### libFuzzer (default)

```sh
# From the repository root
cargo fuzz run --fuzz-dir td-shim/fuzz secure_boot_payload
cargo fuzz run --fuzz-dir td-shim/fuzz secure_boot_cfv
```

Or from within `td-shim/fuzz/`:

```sh
cargo fuzz run secure_boot_payload
cargo fuzz run secure_boot_cfv
```

### AFL

Build and run with the `fuzz` feature enabled:

```sh
# From td-shim/fuzz/
cargo afl build --features fuzz --bin afl_secure_boot_payload
cargo afl fuzz -i seeds/secure_boot_payload -o out/secure_boot_payload \
    target/debug/afl_secure_boot_payload

cargo afl build --features fuzz --bin afl_secure_boot_cfv
cargo afl fuzz -i seeds/secure_boot_cfv -o out/secure_boot_cfv \
    target/debug/afl_secure_boot_cfv
```

### Replaying a Crash (AFL binaries, no fuzzer)

The AFL binaries can also be run without AFL to replay a specific crash file:

```sh
./target/debug/afl_secure_boot_payload <path/to/crash_file>
./target/debug/afl_secure_boot_payload <path/to/crash_dir/>
```
