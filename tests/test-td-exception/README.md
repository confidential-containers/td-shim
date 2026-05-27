# test-td-exception

Integration test crate that runs `td-exception` unit tests inside a bare-metal VM.

## What it tests

Exercises the `td-exception` crate's x86-64 exception handling infrastructure by:

- Verifying that `setup_exception_handlers()` installs the IDT without panicking.
- Asserting initial state of the `DIVIDED_BY_ZERO_EVENT_COUNT` atomic counter (divide-by-zero handler tracking).

Tests run in a `no_std` environment using a custom bootloader entry point so that interrupt handlers are validated on real hardware or a hardware-virtualised environment (QEMU/Intel TDX), not a hosted test runner.

## Running the tests

The `test-runner-server` dev tool must be installed first:

```sh
make install-devtools
```

Then run the integration tests for this crate:

```sh
make integration-test-test-td-exception
```

Or run all integration tests at once:

```sh
make integration-test
```

Under the hood this invokes:

```sh
cargo +nightly-2023-12-31 xtest \
  --target devtools/rustc-targets/x86_64-custom.json \
  -p test-td-exception \
  --release
```
