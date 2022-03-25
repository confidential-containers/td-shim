# test-runner-server & test-runner-client

Rust has a [built-in test framework](https://doc.rust-lang.org/book/ch11-00-testing.html) that is capable of running
unit tests without the need to set anything up.
Just create a function that checks some results through assertions and add the `#[test]` attribute to the function
header. Then `cargo test` will automatically find and execute all test functions of your crate.

Unfortunately it’s a bit more complicated for `#[no_std]` applications such as our case. The problem is that Rust’s
test framework implicitly uses the built-in test library, which depends on the standard library. This means that we
can’t use the default test framework for our `#[no_std]` shim and payload.

To simplify the development, test cases are divided into two classes:
- normal test cases: which may be run on the host (build machine) directly
- vm-based test cases: which must be run inside a virtual machine, the virtual machine may or may not be a trusted
  domain.

It's ease to deal with the normal unit test cases, just include the test cases in the crate source code and use the
normal rust test framework for them.

For vm-based test cases, two fundamental issues must be solved:
- run `#[no_std]` unit test cases. This is solved by making use of the `custom_test_frameworks` feature which allows
  the use of `#[test_case]` and `#![test_runner]`. Any function, const, or static can be annotated with `#[test_case]`
  causing it to be aggregated (like #[test]) and be passed to the test runner determined by the `#![test_runner]`
  crate attribute. The `test-runner-client` provides a `test_runner()` for this purpose.
- run unit test cases inside a vm. The `test-runner-server` prepares a boot disk image and boot a qemu virtual machine
  with the prepared boot image by using the `bootloader` and associated crates. The `test-runner-server` also
  communicates `test-runner-client` through serial port and io port to collect logs and result.
  
And all vm-based test cases are implemented as dedicated crates under directory `tests`.

## Reference
For more detailed design information, please refer to:
- [Writing an OS in Rust: Testing](https://os.phil-opp.com/testing/)
- [How to Build a Custom Test Harness in Rust](https://www.infinyon.com/blog/2021/04/rust-custom-test-harness/)
