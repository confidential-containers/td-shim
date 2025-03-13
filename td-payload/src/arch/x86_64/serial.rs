// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

/// Write a byte to the debug port, converting `\n' to '\r\n`.
fn serial_write_byte(byte: u8) {
    if byte == b'\n' {
        io_write(b'\r')
    }
    io_write(byte)
}

/// Write a string to the debug port.
pub fn serial_write_string(s: &str) {
    for c in s.chars() {
        serial_write_byte(c as u8);
    }
}

const SERIAL_IO_PORT: u16 = 0x3F8;

#[cfg(all(feature = "tdx", not(feature = "no-tdvmcall")))]
fn io_write(byte: u8) {
    tdx_tdcall::tdx::tdvmcall_io_write_8(SERIAL_IO_PORT, byte);
}

#[cfg(all(feature = "tdx", feature = "no-tdvmcall"))]
fn io_write(_byte: u8) {}

#[cfg(not(feature = "tdx"))]
fn io_write(byte: u8) {
    unsafe { x86::io::outb(SERIAL_IO_PORT, byte) };
}
