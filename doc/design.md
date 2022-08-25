# td-shim design

`td-shim` is a lightweight shim firmware for Intel [TDX](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html). It is the initial code in a Trust Domain (TD) - the TDX confidential computing environment.

By design, a hypervisor (such as KVM, cloud-hypervisor, etc) launches `td-shim`, as the initial guest component for a Trust Domain (TD).

`td-shim` owns the reset vector (GPA 0xFFFFFFF0) of the guest TD. It performs below action:
 * initialize the guest TD according to TDX requirement, such as rendez-vous all application processors (AP), switch from 32bit protected mode to 64bit long mode, accept the TD private memory, and extend untrusted VMM input to the TDX Runtime Measurement Register (RTMR) with TD event log for TDX attestation. (Please refer to [Intel TDX Module 1.0 Specification](https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf) and [Intel TDX Virtual Firmware Design Guide](https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-virtual-firmware-design-guide-rev-1.01.pdf) for detail).
 * enable defense in depth, such as data execution prevention (DEP), control flow enforcement technology (CET). (Please refer to [td-shim threat model](threat_model.md) for detail).
 * provide requires information for the next stage payload, such as memory map, ACPI table. (Please refer to [td-shim specification](tdshim_spec.md) for detail)
 * finally, launch the next stage payload - `td-payload`.

`td-payload` could be a bare-metal environment, a UEFI virtual firmware, an OS loader, a OS kernel, etc. `td-shim` supports the multiple td-payload type, which is described by `PAYLOAD_IMAGE_TYPE` in [TD Payload Info GUID Extension HOB](tdshim_spec.md#td-payload-info-guid-extension-hob), such as a PE/COFF or ELF executable image, BzImage/VmLinux image fowllowing Linux Boot Protocol.

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

The [td-shim specification](tdshim_spec.md) defines the interface between td-shim and vmm, and the interface between td-shim and td-payload.

The [td-shim threat model](threat_model.md) defines the threat model for the td-shim.

This repo includes a full `td-shim`, and sample `td-payload`. The consumer may create other td-payload. For example, to support [TDX](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html) [migration TD](https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-migration-td-design-guide-348987-001.pdf), a rust-migtd can include a td-shim and a migtd-payload.

## td-shim

[rust-tdshim](../td-shim) is a core of td-shim. The entrypoint is `_start()` at [main](../td-shim/src/bin/td-shim/main.rs). It will initialize the td-shim and switch to td-payload at `switch_stack_call()` of [main](../td-shim/src/bin/td-shim/main.rs).

The VMM may pass a TD Hand-Off Block (HOB) to the `td-shim` as parameter. The TD HOB is measured and event log is created at `create_td_event()` in [tcg.rs](../td-shim/src/tcg.rs).

Data Execution Prevention (DEP) is setup at `find_and_report_entry_point()` in [ipl.rs](../td-shim/src/ipl.rs). The primitive `set_nx_bit()` and `set_write_protect()` are provided by [memory.rs](../td-shim/src/memory.rs).

Control flow Enforcement Technology (CET) Shadow Stack is setup at `enable_cet_ss()` in [cet_ss.rs](../td-shim/src/bin/td-shim/cet_ss.rs).

Stack guard is setup at `stack_guard_enable()` in [stack_guard.rs](../td-shim/src/stack_guard.rs).

### Reset vector

[ResetVector](../td-shim/ResetVector) is the reset vector inside of the `td-shim`. It owns the first instruction in the TD at address 0xFFFFFFF0. This is implemented in the IA32 code named [resetVector](../td-shim/ResetVector/Ia32/ResetVectorVtf0.asm). The code then switches to long mode, parks application processors (APs), initializes the stack, copies the `td-shim` core to low memory (1MB) and call to `rust-tdshim` via an indirect call `call    rsi` at [main](../td-shim/ResetVector/Main.asm)

### TDX related lib

[tdx-exception](../td-exception) provides execution handler in TD.

[tdx-logger](../td-logger) provides debug logger in TD.

[tdx-tdcall](../td-logger) provides TDCALL function.

### Generic lib

[td-loader](../td-loader) is an PE/ELF image loader.

[td-uefi-pi](../td-uefi-pi) defines uefi-pi data structure and provide uefi-pi structure access function.

[td-paging](../td-paging) provides function to manage the page table.

### External dependency

[ring](../library/ring/) is crypto function. The SHA384 function is used to calculate measurement.

## build

### tools

[td-shim-ld](../td-shim-tools/src/bin/td-shim-ld) is the tool to assembly all components into a TD.bin.

[td-shim-checker](../td-shim-tools/src/bin/td-shim-checker) is the tool to check metatdata of TD.bin.

[td-shim-enroll](../td-shim-tools/src/bin/td-shim-enroll) is the tool to enroll data in CFV of TD.bin.

[td-shim-sign-payload](../td-shim-tools/src/bin/td-shim-sign-payload) is the tool to sign a pyaload binary.

### layout

[td-layout](../td-layout) defines the layout of a TD.

## sample td-payload

[td-payload](../td-payload) is a sample payload. It supports benchmark collection, json parsing.

## test tools

[benchmark](../devtools/td-benchmark) is to help collect benchmark information, such as stack usage, heap usage, execution time.

[fuzzing-test](../fuzzing) includes sample fuzzing test. Refer to [fuzzing](doc/fuzzing.md) doc for more detail.

[test-coverage](doc/unit_test_coverage.md) describes how to collect the coverage data.

[static_analyzer](doc/static_analyzer.md) describes how to scan the vulnerable rust code, such as [rudra](https://github.com/sslab-gatech/Rudra).

[cargo-deny](../.github/workflows/deny.yml) is used to scan the vulnerable rust crate dependency according to [rustsec](https://rustsec.org/).

[no_std_test](../no_std_test) is used to run test for no_std code.

[test_lib](../test_lib) is to provide support function for unit test.
