// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! A simple tool to calculate td-payload and parameter's reference value due to given kernel

use anyhow::*;
use clap::{arg, command, ArgAction};
use parse_int::parse;
use sha2::Digest;
use std::{convert::TryFrom, path::Path};

pub const KERNEL_SIZE: &str = "0x2000000";
pub const KERNEL_PARAM_SIZE: &str = "0x1000";

// Refer to https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#signature-image-only,
// file offset specified at offset 0x3c,
// size of PE signature is 4: "PE\0\0"
const IMAGE_PE_OFFSET: usize = 0x003c;
const PE_SIGNATURE_SIZE: u32 = 4;
const IMGAE_BEGIN_ADDR: usize = 0x0000;

// Refer to https://www.kernel.org/doc/html/latest/arch/x86/boot.html#details-of-header-fields
// Protocol version addr: 0x206, size: 2
const IMAGE_PROTOCOL_ADDR: usize = 0x0206;

fn kernel(path: &str, size: &str) -> Result<String> {
    let path = Path::new(path).to_path_buf();
    let siz = parse::<u64>(size)?;
    let file_size = std::fs::metadata(&path)?.len();
    if file_size > siz {
        bail!("File size should be less than `kernel-size`");
    }
    let buf = std::fs::read(path)?;
    let protocol = ((buf[IMAGE_PROTOCOL_ADDR + 1] as u16) << 8) | buf[IMAGE_PROTOCOL_ADDR] as u16;
    if protocol < 0x206 {
        bail!("Protocol version should be 2.06+");
    }
    padding_digest(buf, siz as usize)
}

fn param(param: &str, size: &str) -> Result<String> {
    let param = Vec::try_from(param)?;
    let siz = parse::<usize>(size)?;
    padding_digest(param, siz)
}

fn qemu(path: &str, size: &str) -> Result<String> {
    let path = Path::new(path).to_path_buf();
    let siz = parse::<u64>(size)?;
    let file_size = std::fs::metadata(&path)?.len();
    if file_size > siz {
        bail!("File size should be less than `kernel-size`");
    }
    let buf = std::fs::read(path)?;
    let protocol = ((buf[IMAGE_PROTOCOL_ADDR + 1] as u16) << 8) | buf[IMAGE_PROTOCOL_ADDR] as u16;
    if protocol < 0x206 {
        bail!("Protocol version should be 2.06+");
    }
    qemu_patch(buf)
}

fn qemu_patch(mut buf: Vec<u8>) -> Result<String> {
    // refer to https://github.com/qemu/qemu/blob/f48c205fb42be48e2e47b7e1cd9a2802e5ca17b0/hw/i386/x86.c#L999
    // patching type_of_loader @0x210
    buf[0x210] = 0xb0;

    // refer to https://github.com/qemu/qemu/blob/f48c205fb42be48e2e47b7e1cd9a2802e5ca17b0/hw/i386/x86.c#L1003
    // patching loadflags @0x211
    buf[0x211] = 0x81;

    // refer to https://github.com/qemu/qemu/blob/9c74490bff6c8886a922008d0c9ce6cae70dd17e/hw/i386/x86.c#L1004
    // patching heap_end_ptr @0x224 cmdline_addr - real_addr - 0x200 = 0xfe00
    buf[0x224] = 0x00;
    buf[0x225] = 0xfe;

    // refer to https://github.com/qemu/qemu/blob/9c74490bff6c8886a922008d0c9ce6cae70dd17e/hw/i386/x86.c#L962
    // patching cmd_line_ptr @0x228 cmdline_addr = 0x20000
    buf[0x228] = 0x00;
    buf[0x229] = 0x00;
    buf[0x22A] = 0x02;
    buf[0x22B] = 0x00;

    let mut hasher = sha2::Sha384::new();
    let (number_of_region_entry, regions_base, regions_size) = get_image_regions(&buf);

    for index in 0..number_of_region_entry {
        hasher.update(&buf[regions_base[index]..regions_base[index] + regions_size[index]]);
    }

    let res = hasher.finalize();
    Ok(hex::encode(res))
}

fn get_image_regions(buf: &[u8]) -> (usize, Vec<usize>, Vec<usize>) {
    // Region 1~3 regions are known.
    let mut number_of_region_entry = 3;
    let mut regions_base = Vec::new();
    let mut regions_size = Vec::new();

    // Refer to https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image,
    // After the signature of an image file is COFF File Header, size is 20 bytes.
    // NumberOfSections       Offset: 2    Size: 2
    let size_of_coff_file_header: u32 = 20;

    let coff_file_header_offset = ((buf[IMAGE_PE_OFFSET + 3] as u32) << 24)
        | ((buf[IMAGE_PE_OFFSET + 2] as u32) << 16)
        | ((buf[IMAGE_PE_OFFSET + 1] as u32) << 8)
        | (buf[IMAGE_PE_OFFSET] as u32) + PE_SIGNATURE_SIZE;

    let number_of_pecoff_entry = ((buf[coff_file_header_offset as usize + 3] as u16) << 8)
        | buf[coff_file_header_offset as usize + 2] as u16;
    number_of_region_entry += number_of_pecoff_entry as usize;

    // SizeOfOptionalHeader   Offset: 16    Size: 2
    let size_of_optional_header = ((buf[coff_file_header_offset as usize + 17] as u16) << 8)
        | buf[coff_file_header_offset as usize + 16] as u16;

    let optional_header_addr: usize = (coff_file_header_offset + size_of_coff_file_header) as usize;

    // Refer to https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-standard-fields-image-only
    // Only support PE32+
    // SizeOfHeaders   Offset: 60      Size: 4
    // CheckSum        Offset: 64      Size: 4
    // Cert table      Offset: 144     Size: 8

    let optional_size_of_headers_offset: usize = 0x003c;
    let optional_checksum_offset: usize = 0x0040;
    let optional_cert_table_offset: usize = 0x0090;

    let size_of_headers =
        ((buf[optional_header_addr + optional_size_of_headers_offset + 3] as u32) << 24)
            | ((buf[optional_header_addr + optional_size_of_headers_offset + 2] as u32) << 16)
            | ((buf[optional_header_addr + optional_size_of_headers_offset + 1] as u32) << 8)
            | buf[optional_header_addr + optional_size_of_headers_offset] as u32;

    // Region 1: from file begin to CheckSum
    regions_base.push(IMGAE_BEGIN_ADDR);
    regions_size.push(optional_header_addr + optional_checksum_offset - IMGAE_BEGIN_ADDR);

    // Region 2: from CheckSum end to certificate table entry
    regions_base.push(optional_header_addr + optional_checksum_offset + 4);
    regions_size.push(optional_cert_table_offset - (optional_checksum_offset + 4));

    // Region 3: from cert table end to Header end
    regions_base.push(optional_header_addr + optional_cert_table_offset + 8);
    regions_size.push(
        size_of_headers as usize - (optional_header_addr + optional_cert_table_offset + 8) as usize,
    );

    // Refer to https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
    // Size Of each Section is 40 bytes
    // SizeOfRawData       Offset: 16      Size:4
    // PointerToRawData    Offset: 20      Size:4
    let mut p = (coff_file_header_offset
        + size_of_coff_file_header
        + size_of_optional_header as u32) as usize;
    for _i in 0..number_of_pecoff_entry {
        p += 16;
        let size = ((buf[p + 3] as u32) << 24)
            | ((buf[p + 2] as u32) << 16)
            | ((buf[p + 1] as u32) << 8)
            | buf[p] as u32;
        p += 4;
        let base = ((buf[p + 3] as u32) << 24)
            | ((buf[p + 2] as u32) << 16)
            | ((buf[p + 1] as u32) << 8)
            | buf[p] as u32;
        regions_base.push(base as usize);
        regions_size.push(size as usize);
        p += 20;
    }
    (number_of_region_entry, regions_base, regions_size)
}

fn padding_digest(mut buf: Vec<u8>, len: usize) -> Result<String> {
    let diff = len - buf.len();

    buf.extend_from_slice(&vec![0; diff as usize]);
    let mut hasher = sha2::Sha384::new();
    hasher.update(&buf);
    let res = hasher.finalize();
    Ok(hex::encode(res))
}

fn main() {
    let matches = command!()
        .subcommand_required(true)
        .subcommand(
            command!("kernel")
                .arg(
                    arg!(-k --kernel "path to vmlinuz kernel")
                        .required(true)
                        .action(ArgAction::Set),
                )
                .arg(
                    arg!(-s --"size" "KERNEL_SIZE of the target td-shim")
                        .required(false)
                        .default_value(KERNEL_SIZE)
                        .action(ArgAction::Set),
                )
                .arg(arg!(-q --"qemu" "QEMU Kernel Direct Boot patch string").required(false)),
        )
        .subcommand(
            command!("param")
                .arg(
                    arg!(-p --parameter "kernel parameter string")
                        .required(true)
                        .action(ArgAction::Set),
                )
                .arg(
                    arg!(-s --"size" "KERNEL_PARAM_SIZE of the target td-shim")
                        .required(false)
                        .default_value(KERNEL_PARAM_SIZE)
                        .action(ArgAction::Set),
                ),
        )
        .get_matches();

    let res = match matches.subcommand() {
        Some(("kernel", args)) => {
            let path = args.get_one::<String>("kernel").unwrap();
            let siz = args.get_one::<String>("size").unwrap();
            // let qflag = args.get_one::<String>("qemu").unwrap();
            if args.get_flag("qemu") {
                qemu(path, siz)
            } else {
                kernel(path, siz)
            }
        }
        Some(("param", args)) => {
            let parameter = args.get_one::<String>("parameter").unwrap();
            let siz = args.get_one::<String>("size").unwrap();
            param(parameter, siz)
        }
        Some((_, _)) => unreachable!(),
        None => unreachable!(),
    };

    match res {
        std::result::Result::Ok(res) => println!("{res}"),
        Err(e) => eprintln!("[ERROR]: {}", e.to_string()),
    }
}
