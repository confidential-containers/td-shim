// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

use log::{Level, Metadata, Record};
use log::{LevelFilter, SetLoggerError};

mod logger;
pub use logger::*;

macro_rules! tdlog {
    ($($arg:tt)*) => (crate::logger::_log_ex(crate::logger::LOG_LEVEL_INFO, crate::logger::LOG_MASK_ALL, format_args!($($arg)*)));
}

/// Logger backend for td-shim.
pub struct LoggerBackend;

impl log::Log for LoggerBackend {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            tdlog!("{} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

/// Logger backend for the log crate
static LOGGER_BACKEND: LoggerBackend = LoggerBackend;

pub fn init() -> Result<(), SetLoggerError> {
    log::set_logger(&LOGGER_BACKEND).map(|()| log::set_max_level(LevelFilter::Info))
}

/// Write a byte to the debug port, converting `\n' to '\r\n`.
pub fn dbg_write_byte(byte: u8) {
    if byte == b'\n' {
        dbg_port_write(b'\r')
    }
    dbg_port_write(byte)
}

/// Write a string to the debug port.
pub fn dbg_write_string(s: &str) {
    #[cfg(feature = "tdg_dbg")]
    {
        // Split long lines by 254 characters when tdg_dbg feature is enabled
        // 254 to account for \n -> \r\n conversion
        s.chars().fold(0usize, |char_count, c| {
            if char_count >= 254 {
                // Insert newline if we've reached the limit
                dbg_write_byte(b'\n');
                // Print the current character
                dbg_write_byte(c as u8);
                // Reset char count
                if c == '\n' {
                    0
                } else {
                    1
                }
            } else {
                dbg_write_byte(c as u8);
                if c == '\n' {
                    0
                } else {
                    char_count + 1
                }
            }
        });
    }

    #[cfg(not(feature = "tdg_dbg"))]
    {
        s.chars().for_each(|c| dbg_write_byte(c as u8));
    }
}

#[cfg(any(
    all(not(feature = "tdx"), feature = "serial-port"),
    all(
        feature = "tdx",
        not(feature = "tdg_dbg"),
        not(feature = "no-tdvmcall")
    ),
    all(not(feature = "tdx"), feature = "serial-port")
))]
const SERIAL_IO_PORT: u16 = 0x3F8;

// tdx, tdg_dbg
#[cfg(all(feature = "tdx", feature = "tdg_dbg"))]
fn dbg_port_write(byte: u8) {
    tdx_tdcall::tdx::tdcall_tdg_debug_write_8(byte);
}

// tdx, !tdg_dbg, no-tdvmcall
#[cfg(all(feature = "tdx", not(feature = "tdg_dbg"), feature = "no-tdvmcall"))]
fn dbg_port_write(_byte: u8) {
    // no-tdvmcall but tdx present, skip port write
}

// tdx, !tdg_dbg, !no-tdvmcall
#[cfg(all(
    feature = "tdx",
    not(feature = "tdg_dbg"),
    not(feature = "no-tdvmcall")
))]
fn dbg_port_write(byte: u8) {
    tdx_tdcall::tdx::tdvmcall_io_write_8(SERIAL_IO_PORT, byte);
}

// !tdx, serial-port
#[cfg(all(not(feature = "tdx"), feature = "serial-port"))]
fn dbg_port_write(byte: u8) {
    unsafe { x86::io::outb(SERIAL_IO_PORT, byte) };
}

// !tdx, !serial-port
#[cfg(not(any(feature = "tdx", feature = "serial-port")))]
fn dbg_port_write(_byte: u8) {
    // fallback
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logger() {
        init().unwrap();

        assert_eq!(LOGGER.lock().get_level(), LOG_LEVEL_INFO);
        LOGGER.lock().set_level(LOG_LEVEL_ERROR);
        assert_eq!(LOGGER.lock().get_level(), LOG_LEVEL_ERROR);

        assert_eq!(LOGGER.lock().get_mask(), LOG_MASK_ALL);
        LOGGER.lock().set_mask(LOG_MASK_COMMON);
        assert_eq!(LOGGER.lock().get_mask(), LOG_MASK_COMMON);

        LOGGER.lock().write_byte(0x1);
        LOGGER.lock().write_string("Hello");

        LOGGER.lock().set_level(LOG_LEVEL_INFO);
        log::error!("just a test");
    }
}
