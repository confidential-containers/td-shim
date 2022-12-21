## Code coverage

### Background

Rust compiler includes a code coverage implementation - enabled with `-C instrument-coverage` which uses LLVM's native, efficient coverage instrumentation to generate very precise coverage data.

After running a coverage-instrumented program, the coverage data write to a `profraw` file. The default `profraw` file name can be override by `LLVM_PROFILE_FILE` environment variable.

The reading and writing of these files requires `std` environment.
But currently td-shim and td-payload are both `no_std` environments.

Currently the code coverage of td-shim/td-payload comes from unit tests which run in the os environment. 

There is currently a lack of methods to obtain code coverage data under no_std.

### Motivation

Get code coverage `profraw` data in `no_std` environment. In this way, the code coverage report of td-shim/td-payload can be obtained。

### How to get code coverage profraw data for `no_std`

1. Get rid of profiler-runtime.
   ```
   export RUSTFLAGS="-Cinstrument-coverage -Zno-profiler-runtime"
   ```
2. Provide a customer LLVM profiling runtime.

   Minicov: https://github.com/Amanieu/minicov
   ```
   minicov = { version="0.2", default-features = false}
   ```
3. Get coverage profiling data.
   ```
   const COVERAGE_DATA_SIZE: usize = 0x300000;
   let coverage_len = minicov::get_coverage_data_size();

   let mut buffer: [u8; COVERAGE_DATA_SIZE] = [0; COVERAGE_DATA_SIZE];

   assert!(actual_size <= COVERAGE_DATA_SIZE, "Not enough space reserved for coverage daa");
   minicov::capture_coverage_to_buffer(&mut buffer[0..actual_size]);
   ```

### How to save profiling data out of Guest/TD

Qemu monitor provide a command called `pmemsave`.
Usage:
```
pmemsave [addr] [size] [file]
```

Note: In the TD environment profiling data need to be saved in shared memory.

### Reference

[Rust compiler Instrument Coverage](https://github.com/rust-lang/rust/blob/master/src/doc/rustc/src/instrument-coverage.md)

[Rust compiler(nightly-2022-05-14 -Z no-profiler-runtime option)](https://github.com/rust-lang/rust/blob/70b3681bf621bc0de91ffab711b2350068b4c466/compiler/rustc_session/src/options.rs#L1368)

[Rust compiler(nightly-2022-05-14) inject of the profiler_builtin crate](https://github.com/rust-lang/rust/blob/70b3681bf621bc0de91ffab711b2350068b4c466/compiler/rustc_metadata/src/creader.rs#L760)

[minicov](https://github.com/Amanieu/minicov)

[qemu monitor](https://qemu.readthedocs.io/en/latest/system/monitor.html)
