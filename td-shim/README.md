# td-shim

The main firmware binary crate for [TD-Shim](../README.md) — a lightweight Intel TDX virtual firmware designed to boot simplified (no-UEFI, no-ACPI-ASL) kernels and payloads inside an Intel Trust Domain (TD).

## What it does

`td-shim` produces a `no_std` / `no_main` bare-metal binary that executes as the virtual firmware of a Trust Domain.
On boot it:

1. **Initialises the hardware environment** — sets up the IDT, configures page tables, and establishes a heap allocator.
2. **Builds the E820 memory map** — derives usable memory ranges from the TD memory layout.
3. **Accepts guest memory** — optionally performs lazy memory acceptance (`lazy-accept` feature).
4. **Parses and verifies the firmware volume (FV)** — locates the payload image embedded in the firmware image.
5. **Optionally verifies secure boot** — validates a cryptographic signature over the payload using ECDSA/RSA via the `ring` crate (`secure-boot` feature, enabled by default).
6. **Loads the payload** — relocates and maps an ELF or PE/COFF payload image into guest memory.
7. **Initialises application processors (APs)** — brings up secondary vCPUs via the TD mailbox protocol.
8. **Emits CC event log entries** — records HOB list, payload binary, and payload parameters into the CCEL (Confidential Computing Event Log) using `cc-measurement`.
9. **Hands off to the payload** — jumps to the payload entry point, passing a HOB (Hand-Off Block) list that carries the E820 map, ACPI tables, and payload info.

## Crate structure

| Path | Purpose |
|---|---|
| `src/lib.rs` | Shared types and GUIDs (E820 HOB, payload info HOB, ACPI HOB) |
| `src/bin/td-shim/main.rs` | Entry point; orchestrates the full boot sequence |
| `src/bin/td-shim/memory.rs` | Memory initialisation and page-table setup |
| `src/bin/td-shim/ipl.rs` | Payload loading — ELF and PE/COFF relocation |
| `src/bin/td-shim/mp.rs` | Multi-processor (AP) wake-up via mailbox |
| `src/bin/td-shim/acpi.rs` | ACPI table construction (CCEL) |
| `src/bin/td-shim/td/` | Intel TDX-specific operations (TDCALLs, mailbox, dummy stubs) |
| `src/secure_boot.rs` | Payload signature verification |
| `src/event_log.rs` | CC measurement / CCEL event logging helpers |
| `src/fv.rs` | Firmware volume parsing |
| `src/reset_vector.rs` | Reset vector metadata helpers |

## Build requirements

The build script (`build.rs`) assembles the reset vector with **NASM** and links the result into the binary.

Required tools:

- **Rust** nightly with `x86_64-unknown-none` target
- **NASM** — must be on `PATH`
- **LLVM / clang** — required when building the `ring` crypto dependency for a bare-metal target; set `CC=clang` and `AR=llvm-ar`

## Features

| Feature | Description |
|---|---|
| `secure-boot` *(default)* | Payload signature verification via `ring` (ECDSA/RSA) |
| `tdx` | Intel TDX TDCALL support and Intel TDX-aware exception handling |
| `lazy-accept` | Lazy guest-physical-memory acceptance (implies `tdx`) |
| `no-tdvmcall` | Build without TDVMCALL (e.g. for unit-test targets) |
| `no-tdaccept` | Build without TDACCEPT |
| `no-metadata-checks` | Disable firmware metadata validation |
| `ring-hash` / `sha2-hash` | Select the hash implementation used for CC measurements |
| `main` | Enables the binary; pulls in allocator, paging, loader, logger, exceptions |

## Key design aspects

- **`no_std` throughout** — no OS or standard library; uses `linked_list_allocator` for the heap.
- **Firmware image layout** — the final firmware image is a flat binary composed of the reset vector, the FV containing the payload, and metadata; layout constants are supplied by the `td-layout` crate at build time.
- **HOB-based hand-off** — follows the PI/UEFI HOB specification to pass structured information to the payload, keeping the interface minimal and well-defined.
- **Pluggable platform layer** — Intel TDX-specific behaviour (`td/tdx.rs`) is compiled in only when the `tdx` feature is active; a no-op `td/dummy.rs` is used otherwise, enabling native unit testing.
