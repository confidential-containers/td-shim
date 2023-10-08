# payload design

`td-shim` supports boot a `td-payload`, which could be a normal OS kernel, or a bare-metal execution environment.

## dependency

A rust-based bare-metal environment for `td-payload` can only have below dependency:

1)	Rust Language `Core` - https://doc.rust-lang.org/core/.

2) 3rd party rust core crates registered at https://crates.io/, after evaluation.

3)	The sharable tdx related crates for bare-metal service.

Examples include crates in [td-shim](https://github.com/confidential-containers/td-shim) project, such as [td-exception](https://github.com/confidential-containers/td-shim/tree/main/td-exception), [tdx-tdcall](https://github.com/confidential-containers/td-shim/tree/main/tdx-tdcall), [td-logger](https://github.com/confidential-containers/td-shim/tree/main/td-logger), [td-paging](https://github.com/confidential-containers/td-shim/tree/main/td-paging) etc, also [rust-spdm](https://github.com/intel/rust-spdm).

## memory footprint

The size of `td-payload` depends on the feature, and it is configurable.

The [td-benchmark](https://github.com/confidential-containers/td-shim/tree/main/devtools/td-benchmark) tool to evaluated the stack and heap usage at runtime. Please refere to [test_heap_stack_usage](https://github.com/confidential-containers/td-shim/blob/main/doc/test_heap_stack_usage.md).

For example:
1) [MigTD](https://github.com/intel/MigTD)

8M image and 32M runtime memory. They are configured at https://github.com/intel/MigTD/blob/main/config/metadata.json.

2) [vtpm-td](https://github.com/intel/vtpm-td)

8M image and 32M runtime memory. They are configured at https://github.com/intel/vtpm-td/blob/main/config/metadata.json.

## memory allocation

We can use rust core alloc crate.

For example: [linked_list_allocateor](https://github.com/rust-osdev/linked-list-allocator)

## crypto support

Td-payload can use rust crypto libraries, such as [ring](https://github.com/briansmith/ring), [webpki](https://github.com/briansmith/webpki), or [rust-mbedtls](https://github.com/fortanix/rust-mbedtls), which support `no-std`.

But [rustls](https://github.com/rustls/rustls) and [rust-openssl](https://github.com/sfackler/rust-openssl) require rust `std` support.

To support linking different crypto crate, the consumer has better use crypto traits, such as https://github.com/RustCrypto/traits.

