# td-logger

A simple `no_std` logging backend for [td-shim](https://github.com/confidential-containers/td-shim), a Confidential Computing shim for Intel TDX, providing two complementary logging mechanisms:

1. **`log` crate integration** — A [`LoggerBackend`] struct that implements `log::Log`, routing standard `log` macros (`info!`, `warn!`, `error!`, etc.) to the debug output port.
2. **Standalone logger** — A [`Logger`] struct with level and subsystem-mask filtering, usable independently of the `log` crate via `_log_ex` and `_log`.

Output is written to a hardware debug port (I/O port `0x3F8` / serial, or via Intel TDX TDVMCALL/TDG.VP.VMCALL, depending on enabled features).

## Key Items

### Types

| Item | Description |
|------|-------------|
| `LoggerBackend` | Implements `log::Log`; use with `log::set_logger` |
| `Logger` | Low-level logger with `level` and `mask` fields; protected by a `spin::Mutex` |
| `LOGGER` | Global `Mutex<Logger>` instance (`lazy_static`) |

### Functions

| Function | Description |
|----------|-------------|
| `init(max_level: LevelFilter)` | Registers `LoggerBackend` with the `log` crate and sets the max log level |
| `_log_ex(level, mask, args)` | Logs with level + subsystem-mask filtering (used internally by `tdlog!`) |
| `_log(args)` | Logs unconditionally through the global `LOGGER` |
| `dbg_write_byte(byte: u8)` | Writes a single byte to the debug port (`\n` → `\r\n`) |
| `dbg_write_string(s: &str)` | Writes a string to the debug port |

### Log Level Constants (`logger` module)

```
LOG_LEVEL_TRACE = 5
LOG_LEVEL_DEBUG = 4
LOG_LEVEL_INFO  = 3
LOG_LEVEL_WARN  = 2
LOG_LEVEL_ERROR = 1
LOG_LEVEL_NONE  = 0
```

### Log Mask Constants

```
LOG_MASK_COMMON = 0x1
LOG_MASK_ALL    = 0xFFFFFFFFFFFFFFFF
```

## Usage

### With the `log` crate

```rust
use log::LevelFilter;

td_logger::init(LevelFilter::Info).expect("Failed to initialize logger");

log::info!("td-shim started");
```

### Direct logging (no `log` crate)

```rust
use td_logger::logger::{_log_ex, LOG_LEVEL_INFO, LOG_MASK_ALL};

_log_ex(LOG_LEVEL_INFO, LOG_MASK_ALL, format_args!("hello from td-shim\n"));
```

### Adjusting level and mask at runtime

```rust
use td_logger::logger::{LOGGER, LOG_LEVEL_DEBUG, LOG_MASK_ALL};

LOGGER.lock().set_level(LOG_LEVEL_DEBUG);
LOGGER.lock().set_mask(LOG_MASK_ALL);
```

## Features

| Feature | Description |
|---------|-------------|
| `tdx` | Use Intel TDX TDVMCALL (`tdvmcall_io_write_8`) for port I/O |
| `serial-port` | Use x86 `outb` for serial port output (non-Intel TDX environments) |
| `no-tdvmcall` | Disable TDVMCALL port writes when running in Intel TDX without VMCall support |
| `tdg_dbg` | Use `TDG.VP.VMCALL<TDG.MEM.DEBUG.WRITE8>` for debug output; splits lines at 254 characters |
