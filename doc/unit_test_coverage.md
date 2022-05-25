# Unit Test Code Covergae Guide
This guide will introduce 3 kinds of tools(gcov, kcov and cargo-tarpaulin) to collect test code coverage for Rust project. All the tools can run on popular CI tools like Travis.

## gcov
Gcov is a source code coverage analysis and statement-by-statement profiling tool. Gcov generates exact counts of the number of times each statement in a program is executed and annotates source code to add instrumentation. Linux, macOS and Windows are supported. It is also support other test like fuzzing and provides more accurate code coverage data. So we prefer to use this tool in TD-Shim. 

### Installation
Install grcov with cargo:
```
$ cargo install grcov
```
Install the llvm-tools Rust component (`llvm-tools-preview` for now, it might become `llvm-tools` soon):
```
$ rustup component add llvm-tools-preview
```

### Run Unit Test & Collect Code Coverage
#### Generate source-based coverage for a Rust project
```
$ export RUSTFLAGS="-Cinstrument-coverage"
```
Ensure each test runs gets its own profile information by defining the LLVM_PROFILE_FILE environment variable (%p will be replaced by the process ID, and %m by the binary signature):
```
$ export LLVM_PROFILE_FILE="your_name-%p-%m.profraw"
```
Run tests:
```
$ cargo test
```
Generate a HTML report in the coverage/ directory:
```
$ grcov . --binary-path ./target/debug/ -s . -t html --branch --ignore-not-existing -o ./target/debug/coverage/
```

You can see the report in `target/debug/coverage/index.html`.

## kcov
Kcov is a FreeBSD/Linux/OSX code coverage tester for compiled languages, Python and Bash. Kcov was originally a fork of Bcov, but has since evolved to support a large feature set in addition to that of Bcov.

### Limitation
The tool being used, kcov, is not Rust-specific. It uses DWARF debugging information in your generated executable to determine which lines have been covered. [kcov does not always generate the most accurate coverage information.](https://stackoverflow.com/questions/32521800/why-does-kcov-calculate-incorrect-code-coverage-statistics-for-rust-programs)

kcov will likely only work for x86 and x86_64 Linux.

### Installation
To install using apt:
```
$ sudo apt-get install kcov
```
Once installed, check your kcov version use the `--version` argument:
```
$ kcov --version
```

### Run Unit Test & Collect Code Coverage
To collect coverage data, first generate your test executable without running it:
```
$ cargo test --no-run
```
The compiled binaries are placed in `target/debug/deps`. Cargo may create multiple test executables if you have multiple binaries. Note that Cargo will postfix the test binary names with a hash, e.g. `<executable name>-012954d6a8535cff`, so make sure to pick the latest of these binaries for the next step.

To run your tests and collect coverage, run kcov with the following command:
```
$ kcov --exclude-pattern=/.cargo,/usr/lib --verify target/cov target/debug/<executable name>
```
You can see the report in `target/cov/index.html`.

Note: If collecting coverage for multiple test executables, make sure you are not inadvertently overwriting the coverage data of one of your other executables. When you run kcov, it will automatically store coverage in a directory named after the full name of the executable you pass in. It will also merge any coverage it finds each time you run it for a different executable. This may cause some lines to appear uncovered even though they are covered in another test executable. Whether or not things are merged should not be an issue for Codecov because it will automatically search for and merge all of your coverage data automatically. Coveralls should be able to do this as well.

## cargo-tarpaulin
Tarpaulin is designed to be a code coverage reporting tool for the Cargo build system. Currently, tarpaulin provides working line coverage but is still in the early development stage and therefore may contain some bugs.

### Limitation
Tarpaulin only supports x86_64 processors running linux. This is because instrumenting breakpoints into executables and tracing their execution requires processor and OS specific code.

It can only run the unit test cases of default-members. It is not flexible and does not support other test cases like fuzzing test case. 

### Installation
```
$ cargo install cargo-tarpaulin
```

### Run Unit Test & Collect Code Coverage
```
$ cargo tarpaulin
$ cargo tarpaulin --out html # Generate html report
```
You can see the report named `tarpaulin-report.html`.

Reference:

​[rust-code-coverage-sample](https://github.com/marco-c/rust-code-coverage-sample) \
[grcov-with-travis](https://github.com/mozilla/grcov#grcov-with-travis) \
[rust-code-coverage](https://sunjay.dev/2016/07/25/rust-code-coverage) \
[cargo-tarpaulin](https://crates.io/crates/cargo-tarpaulin)