# cc-measurement

A `no_std` crate providing Confidential Computing measurement and TCG event log support for td-shim. It records measurements into Intel TDX Runtime Measurement Registers (RTMRs) and maintains a TCG2-compatible event log, implementing structures defined in the [TCG PC Client Platform Firmware Profile Specification](https://trustedcomputinggroup.org/resource/pc-client-platform-firmware-profile-specification/) with SHA-384 digest support.

## Key Types

### Event Log Structures (`lib.rs`)

| Type | Description |
|------|-------------|
| `TcgEfiSpecIdevent` | First event in the log; identifies log version and digest algorithms (`Spec ID Event03`) |
| `TcgEfiSpecIdEventAlgorithmSize` | Algorithm ID and digest size entry within `TcgEfiSpecIdevent` |
| `CcEventHeader` | Header for a CC (Confidential Computing) event, containing MR index, event type, and SHA-384 digest |
| `TpmlDigestValues` | Packed list of digests (SHA-384, one entry) |
| `TpmtHa` / `TpmuHa` | TPM hash algorithm identifier and raw digest value |
| `TcgPcrEventHeader` | Legacy PCR event header used for the initial `TCG_EfiSpecIDEvent` record |
| `UefiPlatformFirmwareBlob2` | Encodes firmware blob base/length info for `EV_EFI_PLATFORM_FIRMWARE_BLOB2` events |

### Event Log Writer/Reader (`log.rs`)

| Type | Description |
|------|-------------|
| `CcEventLogWriter` | Writes events into a caller-provided byte slice, hashes data with SHA-384, and extends RTMRs via an injected callback |
| `CcEventLogReader` | Parses a raw event log buffer, exposing the spec ID event and an iterator over subsequent CC events |
| `CcEvents` | `Iterator` over `(CcEventHeader, event_data)` pairs within a log buffer |
| `CcEventLogError` | Error type: `InvalidParameter`, `OutOfResource`, `InvalidMrIndex`, `ExtendMr` |

### Event Type Constants

```rust
EV_NO_ACTION              // 0x00000003
EV_SEPARATOR              // 0x00000004
EV_PLATFORM_CONFIG_FLAGS  // 0x0000000A
EV_EFI_PLATFORM_FIRMWARE_BLOB2 // 0x8000000A
EV_EFI_HANDOFF_TABLES2    // 0x8000000B
```

## Usage Notes

- **`no_std`** — requires `alloc`.
  Suitable for firmware/shim environments.
- **Hash backend** — SHA-384 is provided by `sha2` (default, software-only) or `ring` (select via the `ring` feature).
  Exactly one must be active.
- **RTMR extension** — `CcEventLogWriter::new` accepts a `Box<dyn Fn(&[u8; 48], u32) -> Result<()>>` callback responsible for extending the actual RTMR.
  The crate does not perform the Intel TDX `TDCALL` itself.
- **Log layout** — The first entry is always a `TcgPcrEventHeader` + `TcgEfiSpecIdevent`.
  All subsequent entries use `CcEventHeader`.

### Writing events

```rust
let mut log_buf = [0u8; 4096];
let mut writer = CcEventLogWriter::new(
    &mut log_buf,
    Box::new(|digest, mr_index| {
        // call tdx_tdcall::tdreport or similar to extend RTMR
        Ok(())
    }),
).unwrap();

writer.create_event_log(
    1,                           // mr_index (RTMR index)
    EV_EFI_PLATFORM_FIRMWARE_BLOB2,
    &[event_data_slice],
    hash_input,
).unwrap();

writer.create_seperator().unwrap(); // extends RTMR[0] and RTMR[1]
```

### Reading events

```rust
let reader = CcEventLogReader::new(&log_buf).unwrap();
for (header, data) in reader.cc_events {
    println!("{}", header);
}
```
