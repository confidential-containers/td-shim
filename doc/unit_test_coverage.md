### source coded coverage

**grcov has a bug in Windows, please run the command line with administrator**

​	[bug issues](https://github.com/mozilla/grcov/issues/561)


First of all, install grcov
```sh
cargo install grcov
```

Second, install the llvm-tools Rust component (`llvm-tools-preview` for now, it might become `llvm-tools` soon):
```sh
rustup component add llvm-tools-preview
```

# Generate source-based coverage

```sh
# Export the flags needed to instrument the program to collect code coverage.
export RUSTFLAGS="-Zinstrument-coverage"

# Ensure each test runs gets its own profile information by defining the LLVM_PROFILE_FILE environment variable (%p will be replaced by the process ID, and %m by the binary signature):
export LLVM_PROFILE_FILE="your_name-%p-%m.profraw"

# test the program
cargo test

# Generate a HTML report in the coverage/ directory.
grcov . --binary-path ./target/debug/ -s . -t html --branch --ignore-not-existing -o ./target/debug/coverage/

# Unset RUSTFLAGS and LLVM_PROFILE_FILE environment variable
unset RUSTFLAGS
unset LLVM_PROFILE_FILE
```

# View report:
```sh
browser open the target/debug/coverage/index.html
```
Reference:

​[rust-code-coverage-sample](https://github.com/marco-c/rust-code-coverage-sample)

​	[source_based_code_coverage](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/source-based-code-coverage.html#running-the-instrumented-binary-to-generate-raw-coverage-profiling-data)

​	[grcov](https://github.com/mozilla/grcov)
