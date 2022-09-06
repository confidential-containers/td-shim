// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::fmt::Write;

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => (serial(format_args!($($arg)*)));
}

struct Serial;

impl core::fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        serial_write_string(s);
        Ok(())
    }
}

/// Write a byte to the debug port, converting `\n' to '\r\n`.
fn serial_write_byte(byte: u8) {
    if byte == b'\n' {
        io_write(b'\r')
    }
    io_write(byte)
}

/// Write a string to the debug port.
fn serial_write_string(s: &str) {
    for c in s.chars() {
        serial_write_byte(c as u8);
    }
}

const SERIAL_IO_PORT: u16 = 0x3F8;

#[cfg(feature = "tdx")]
fn io_write(byte: u8) {
    let _ = tdx_tdcall::tdx::tdvmcall_io_write_8(SERIAL_IO_PORT, byte);
}

#[cfg(not(feature = "tdx"))]
fn io_write(byte: u8) {
    unsafe { x86::io::outb(SERIAL_IO_PORT, byte) };
}

/// Log the message with level and subsystem filtering.
pub fn serial(args: core::fmt::Arguments) {
    let mut serial = Serial {};
    serial.write_fmt(args).expect("Failed to write serial");
}
