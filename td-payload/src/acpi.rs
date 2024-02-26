// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use scroll::Pread;
use spin::Once;
use td_shim::TD_ACPI_TABLE_HOB_GUID;
use td_shim_interface::td_uefi_pi::{
    hob as hob_lib,
    pi::hob::{GuidExtension, Header, HOB_TYPE_END_OF_HOB_LIST, HOB_TYPE_GUID_EXTENSION},
};

use crate::Error;

pub type AcpiTable = &'static [u8];

static ACPI_TBALES: Once<Vec<AcpiTable>> = Once::new();

pub fn init_acpi_tables(hob: &'static [u8]) -> Result<(), Error> {
    let mut acpi_tables = Vec::new();
    let mut offset = 0;

    loop {
        let block = &hob[offset..];
        let header: Header = block.pread(0).map_err(|_| Error::ParseHob)?;

        match header.r#type {
            HOB_TYPE_GUID_EXTENSION => {
                let header: GuidExtension = block.pread(0).map_err(|_| Error::ParseHob)?;
                if &header.name == TD_ACPI_TABLE_HOB_GUID.as_bytes() {
                    acpi_tables.push(parse_guided_hob(block)?);
                }
            }
            HOB_TYPE_END_OF_HOB_LIST => {
                // End of the hob list, break the loop
                break;
            }
            _ => {}
        }
        offset = hob_lib::align_to_next_hob_offset(hob.len(), offset, header.length)
            .ok_or(Error::ParseHob)?;
    }

    ACPI_TBALES.call_once(|| acpi_tables);

    Ok(())
}

fn parse_guided_hob(guided_hob: &'static [u8]) -> Result<AcpiTable, Error> {
    let acpi_table = hob_lib::get_guid_data(guided_hob).ok_or(Error::ParseHob)?;

    Ok(acpi_table)
}

pub fn get_acpi_tables() -> Option<&'static [AcpiTable]> {
    ACPI_TBALES.get().map(|tables| tables.as_slice())
}
