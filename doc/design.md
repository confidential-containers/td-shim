# td-shim design

`td-shim` is a lightweight shim firmware for Intel [TDX](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html). It is the initial code in a Trust Domain (TD) - the TDX confidential computing environment.

By design, a hypervisor (such as KVM, cloud-hypervisor, etc) launches `td-shim`, as the initial guest component for a Trust Domain (TD).

`td-shim` owns the reset vector (GPA 0xFFFFFFF0) of the guest TD. It performs below action:
 * initialize the guest TD according to TDX requirement, such as rendez-vous all application processors (AP), switch from 32bit protected mode to 64bit long mode, accept the TD private memory, and extend untrusted VMM input to the TDX Runtime Measurement Register (RTMR) with TD event log for TDX attestation. (Please refer to [Intel TDX Module 1.0 Specification](https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf) and [Intel TDX Virtual Firmware Design Guide](https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-virtual-firmware-design-guide-rev-1.01.pdf) for detail).
 * enable defense in depth, such as data execution prevention (DEP), control flow enforcement technology (CET). (Please refer to [td-shim threat model](https://github.com/confidential-containers/td-shim/blob/main/doc/threat_model.md) for detail).
 * provide requires information for the next stage payload, such as memory map, ACPI table. (Please refer to [td-shim specification](https://github.com/confidential-containers/td-shim/blob/main/doc/tdshim_spec.md) for detail)
 * finally, launch the next stage payload - `td-payload`.

`td-payload` could be a bare-metal environment, a UEFI virtual firmware, an OS loader, a OS kernel, etc. `td-shim` supports the multiple td-payload type, which is described by `PAYLOAD_IMAGE_TYPE` in [TD Payload Info GUID Extension HOB](https://github.com/jyao1/td-shim/blob/main/doc/tdshim_spec.md#td-payload-info-guid-extension-hob), such as a PE/COFF or ELF executable image, BzImage/VmLinux image fowllowing Linux Boot Protocol.

Below figure shows the high level design.

   ```
                     +----------------------+
                     |       td-payload     |
                     |                      |
                     +----------------------+
                                 ^
                                 | <-------------------- td-shim spec
                     +----------------------+
                     |        td-shim       |
                     |           ^          |
                     |           |          |
                     |     (reset vector)   |
      Guest          +----------------------+
      ============================================ <--- td-shim spec
      Host           +----------------------+
                     |         VMM          |
                     +----------------------+

   ```

The [td-shim specification](https://github.com/confidential-containers/td-shim/blob/main/doc/tdshim_spec.md) defines the interface between td-shim and vmm, and the interface between td-shim and td-payload.

The [td-shim threat model](https://github.com/confidential-containers/td-shim/blob/main/doc/threat_model.md) defines the threat model for the td-shim.

This repo includes a full `td-shim`, and sample `td-payload`. The consumer may create other td-payload. For example, to support [TDX](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html) [migration TD](https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-migration-td-design-guide-348987-001.pdf), a rust-migtd can include a td-shim and a migtd-payload.

## td-shim

[rust-tdshim](https://github.com/confidential-containers/td-shim/tree/main/rust-tdshim) is a core of td-shim. The entrypoint is `_start()` at [main](https://github.com/confidential-containers/td-shim/blob/main/rust-tdshim/src/main.rs). It will initialize the td-shim and switch to td-payload at `switch_stack_call()` of [main](https://github.com/confidential-containers/td-shim/blob/main/rust-tdshim/src/main.rs).

The VMM may pass a TD Hand-Off Block (HOB) to the `td-shim` as parameter. The TD HOB is measured and event log is created at `create_td_event()` in [tcg.rs](https://github.com/confidential-containers/td-shim/blob/main/rust-tdshim/src/tcg.rs).

Data Execution Prevention (DEP) is setup at `find_and_report_entry_point()` in [ipl.rs](https://github.com/confidential-containers/td-shim/blob/main/rust-tdshim/src/ipl.rs). The primitive `set_nx_bit()` and `set_write_protect()` are provided by [memory.rs](https://github.com/confidential-containers/td-shim/blob/main/rust-tdshim/src/memory.rs).

Control flow Enforcement Technology (CET) Shadow Stack is setup at `enable_cet_ss()` in [cet_ss.rs](https://github.com/confidential-containers/td-shim/blob/main/rust-tdshim/src/cet_ss.rs).

Stack guard is setup at `stack_guard_enable()` in [stack_guard.rs](https://github.com/confidential-containers/td-shim/blob/main/rust-tdshim/src/stack_guard.rs).

### Reset vector

[ResetVector](https://github.com/confidential-containers/td-shim/tree/main/rust-tdshim/ResetVector) is the reset vector inside of the `td-shim`. It owns the first instruction in the TD at address 0xFFFFFFF0. This is implemented in the IA32 code named [resetVector](https://github.com/confidential-containers/td-shim/blob/main/rust-tdshim/ResetVector/Ia32/ResetVectorVtf0.asm). The code then switches to long mode, parks application processors (APs), initializes the stack, copies the `td-shim` core to low memory (1MB) and call to `rust-tdshim` via an indirect call `call    rsi` at [main](https://github.com/confidential-containers/td-shim/blob/main/rust-tdshim/ResetVector/Main.asm)

### TDX related lib

[tdx-exception](https://github.com/confidential-containers/td-shim/tree/main/tdx-exception) provides execution handler in TD.

[tdx-logger](https://github.com/confidential-containers/td-shim/tree/main/tdx-logger) provides debug logger in TD.

[tdx-tdcall](https://github.com/confidential-containers/td-shim/tree/main/tdx-logger) provides TDCALL function.

### Generic lib

[elf-loader](https://github.com/confidential-containers/td-shim/tree/main/elf-loader) is an ELF image loader.

[pe-loader](https://github.com/confidential-containers/td-shim/tree/main/pe-loader) is an PE image loader.

[fw-pci](https://github.com/confidential-containers/td-shim/tree/main/fw-pci) provides the access to PCI space.

[fw-virtio](https://github.com/confidential-containers/td-shim/tree/main/fw-virtio) provides virtio interface.

[fw-vsock](https://github.com/confidential-containers/td-shim/tree/main/fw-vsock) provides vsock interface.

[r-uefi-pi](https://github.com/confidential-containers/td-shim/tree/main/r-uefi-pi) defines uefi-pi data structure.

[uefi-pi](https://github.com/confidential-containers/td-shim/tree/main/uefi-pi) provide uefi-pi structure access function.

[rust-paging](https://github.com/confidential-containers/td-shim/tree/main/rust-paging) provides function to manage the page table.

### External dependency

[ring](https://github.com/jyao1/ring/tree/uefi_support) is crypto function. The SHA384 function is used to calculate measurement.

## build

### tools

[rust-td-tool](https://github.com/confidential-containers/td-shim/tree/main/rust-td-tool) is the tool to assembly all components into a TD.bin.

### layout

[rust-td-layout](https://github.com/confidential-containers/td-shim/tree/main/rust-td-layout) defines the layout of a TD.

## sample td-payload

[rust-td-payload](https://github.com/confidential-containers/td-shim/tree/main/rust-td-payload) is a sample payload. It supports benchmark collection, json parsing.

## test tools

[benchmark](https://github.com/confidential-containers/td-shim/tree/main/benchmark) is to help collect benchmark information, such as stack usage, heap usage, execution time.

[fuzzing-test](https://github.com/confidential-containers/td-shim/tree/main/fuzzing) includes sample fuzzing test. Refer to [fuzzing](https://github.com/confidential-containers/td-shim/blob/main/doc/fuzzing.md) doc for more detail.

[test-coverage](https://github.com/confidential-containers/td-shim/blob/main/doc/unit_test_coverage.md) describes how to collect the coverage data.

[rudra](https://github.com/confidential-containers/td-shim/blob/main/doc/rudra.md) describes how to scan the vulnerable rust code by using [rudra](https://github.com/sslab-gatech/Rudra).

[cargo-deny](https://github.com/confidential-containers/td-shim/blob/main/.github/workflows/deny.yml) is used to scan the vulnerable rust crate dependency according to [rustsec](https://rustsec.org/).

[no_std_test](https://github.com/confidential-containers/td-shim/tree/main/no_std_test) is used to run test for no_std code.

[test_lib](https://github.com/confidential-containers/td-shim/tree/main/test_lib) is to provide support function for unit test.
