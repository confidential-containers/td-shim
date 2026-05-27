# test-td-payload

A `no_std` integration test payload that runs Intel TDX hardware-specific test cases as a td-payload inside a Trust Domain. It exercises TD-Shim and td-payload functionality that can only be validated on real Intel TDX hardware or an Intel TDX-capable VMM. Test cases are driven by JSON configuration files that supply expected values and control which cases are enabled for a given vCPU/memory combination.

## Test Cases

| ID | Module | What is tested |
|----|--------|----------------|
| tcs001–004 | `testtdinfo` | `TDCALL[TDG.VP.INFO]` — guest physical address width, vCPU count, attributes |
| tcs006 | `testtdreport` | `TDCALL[TDG.MR.REPORT]` — TD report generation and structure |
| tcs007 | `testiorw8` | 8-bit I/O port read/write via `#VE` emulation |
| tcs008 | `testiorw32` | 32-bit I/O port read/write via `#VE` emulation |
| tcs009 | `testtdve` | Virtualization exception (`#VE`) handling |
| tcs010 | `testacpi` | ACPI table presence and correctness in HOB |
| tcs011–015 | `testmemmap` | E820 memory map across vCPU/memory configurations |
| tcs016 | `testtrustedboot` | CC event log (CCEL/RTMR) integrity and measurement correctness |
| — | `testcetibt` | CET indirect branch tracking (IBT) in td-payload |
| — | `testcetshstk` | CET shadow stack (SHSTK) in td-payload |
| — | `teststackguard` | Stack guard page protection in td-payload |

## Configuration

Test inputs and expected values are provided via JSON files in [config/](config/).
Five configurations cover different vCPU and memory combinations:

| File | vCPUs | Memory |
|------|-------|--------|
| `test_config_1.json` | 1 | 1 GB |
| `test_config_2.json` | 1 | 2 GB |
| `test_config_3.json` | 2 | 4 GB |
| `test_config_4.json` | 4 | 8 GB |
| `test_config_5.json` | 8 | 16 GB |

Each test case entry has a `run` boolean flag; set it to `false` to skip a case.

## Building

Build the payload binary using the workspace `xtask`:

```sh
cargo xtask build-test-td-payload
```

Or directly:

```sh
cargo build -p test-td-payload --features tdx,main --target x86_64-unknown-none
```

## Running

The payload must be launched inside an Intel TDX-enabled VM via td-shim.
Refer to [doc/test_with_td_payload.md](../../doc/test_with_td_payload.md) and the integration test script for full launch instructions:

```sh
sh_script/integration_tdx.sh
```

The test binary reads its configuration from the TD payload HOB region.
Pass the desired config JSON path to the launch script or embed it during image construction.
