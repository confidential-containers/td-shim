// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

extern crate alloc;
use core::fmt;
use lazy_static::lazy_static;
use scroll::{Pread, Pwrite};
use spin::Mutex;

use crate::tdx;

pub const TD_REPORT_SIZE: usize = 0x400;
pub const TD_REPORT_ADDITIONAL_DATA_SIZE: usize = 64;
const TD_REPORT_BUFF_SIZE: usize = 0x840; // TD_REPORT_SIZE*2 + TD_REPORT_ADDITIONAL_DATA_SIZE
const TDCALL_TDREPORT: u64 = 4;

#[derive(Debug, Pread, Pwrite)]
pub struct ReportType {
    pub r#type: u8,
    pub subtype: u8,
    pub version: u8,
    pub reserved: u8,
}
#[derive(Debug, Pread, Pwrite)]
pub struct ReportMac {
    pub report_type: ReportType,
    reserved0: [u8; 12],
    pub cpu_svn: [u8; 16],
    pub tee_tcb_info_hash: [u8; 48],
    pub tee_info_hash: [u8; 48],
    pub report_data: [u8; 64],
    reserved1: [u8; 32],
    pub mac: [u8; 32],
}

impl fmt::Display for ReportMac {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Report MAC:\n\tReport Type:\n\ttype: {:x?}\tsubtype: {:x?}\
                        \tversion: {:x?}\n\tCPU SVN:\n\t{:x?}\n\
                        \tTEE TCB Info Hash:\n\t{:x?}\n\tTEE Info Hash:\n\t{:x?}\n\
                        \tReport Data:\n\t{:x?}\n\tMAC:\n\t{:x?}\n",
            self.report_type.r#type,
            self.report_type.subtype,
            self.report_type.version,
            self.cpu_svn,
            self.tee_tcb_info_hash,
            self.tee_info_hash,
            self.report_data,
            self.mac
        )
    }
}

#[derive(Debug, Pread, Pwrite)]
pub struct TeeTcbInfo {
    pub valid: [u8; 8],
    pub tee_tcb_svn: [u8; 16],
    pub mrseam: [u8; 48],
    pub mrsigner_seam: [u8; 48],
    pub attributes: [u8; 8],
    reserved: [u8; 111],
}

impl fmt::Display for TeeTcbInfo {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TEE TCB Info:\n\tValid:\n\t{:x?}\n\tTEE TCB SVN:\n\t{:x?}\n\
                        \tMR SEAM:\n\t{:x?}\n\tMR Signer SEAM:\n\t{:x?}\n\
                        \tAttributes:\n\t{:x?}\n",
            self.valid, self.tee_tcb_svn, self.mrseam, self.mrsigner_seam, self.attributes
        )
    }
}

#[derive(Debug, Pread, Pwrite)]
pub struct TdInfo {
    pub attributes: [u8; 8],
    pub xfam: [u8; 8],
    pub mrtd: [u8; 48],
    pub mrconfig_id: [u8; 48],
    pub mrowner: [u8; 48],
    pub mrownerconfig: [u8; 48],
    pub rtmr0: [u8; 48],
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub rtmr3: [u8; 48],
    reserved: [u8; 112],
}

impl fmt::Display for TdInfo {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TdInfo:\n\tAttributes:\n\t{:x?}\n\txfam:\n\t{:x?}\n\
                        \tMR TD:\n\t{:x?}\n\tMR Config ID:\n\t{:x?}\n\
                        \tMR Owner:\n\t{:x?}\n\tMR Owner Config:\n\t{:x?}\n\
                        \tRTMR[0]:\n\t{:x?}\n\tRTMR[1]:\n\t{:x?}\n\
                        \tRTMR[2]:\n\t{:x?}\n\tRTMR[3]:\n\t{:x?}\n",
            self.attributes,
            self.xfam,
            self.mrtd,
            self.mrconfig_id,
            self.mrowner,
            self.mrownerconfig,
            self.rtmr0,
            self.rtmr1,
            self.rtmr2,
            self.rtmr3
        )
    }
}

#[repr(C, packed)]
#[derive(Debug, Pread, Pwrite)]
pub struct TdxReport {
    pub report_mac: ReportMac,
    pub tee_tcb_info: TeeTcbInfo,
    reserved: [u8; 17],
    pub td_info: TdInfo,
}

impl fmt::Display for TdxReport {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TDX Report:\n{}\n{}\n{}\n",
            self.report_mac, self.tee_tcb_info, self.td_info
        )
    }
}

impl TdxReport {
    fn from(raw: &[u8]) -> Option<TdxReport> {
        if raw.len() != TD_REPORT_SIZE {
            None
        } else {
            let report: TdxReport = raw.pread(0).ok()?;
            Some(report)
        }
    }

    pub fn to_buff(&self) -> [u8; TD_REPORT_SIZE] {
        let mut buff: [u8; TD_REPORT_SIZE] = [0; TD_REPORT_SIZE];
        buff.pwrite(self, 0).unwrap();
        buff
    }
}

lazy_static! {
    static ref TD_REPORT: Mutex<[u8; TD_REPORT_BUFF_SIZE]> = Mutex::new([0; TD_REPORT_BUFF_SIZE]);
}

pub fn tdcall_report(additional_data: &[u8]) -> TdxReport {
    let mut tdreport_buff = TD_REPORT.lock();
    let address = tdreport_buff.as_ptr() as usize;

    let report_offset: usize = (TD_REPORT_SIZE - address) & (TD_REPORT_SIZE - 1);
    let data_offset: usize = report_offset + TD_REPORT_SIZE;

    tdreport_buff[data_offset..data_offset + TD_REPORT_ADDITIONAL_DATA_SIZE]
        .copy_from_slice(additional_data);

    let buffer: u64 =
        tdreport_buff[report_offset..].as_mut_ptr() as *mut core::ffi::c_void as usize as u64;

    let ret = unsafe {
        tdx::td_call(
            TDCALL_TDREPORT,
            buffer,
            buffer + TD_REPORT_SIZE as u64,
            0,
            0,
        )
    };
    if ret != tdx::TDX_EXIT_REASON_SUCCESS {
        tdx::tdvmcall_halt();
    }

    TdxReport::from(&tdreport_buff[report_offset..report_offset + TD_REPORT_SIZE]).unwrap()
}

pub fn tdreport_dump() {
    let addtional_data: [u8; 64] = [0; 64];
    let tdx_report = tdcall_report(&addtional_data);
    log::info!("{}", tdx_report);
}
