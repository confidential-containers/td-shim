// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::fmt;
use core::mem::{size_of, zeroed};
use core::ptr::{slice_from_raw_parts, slice_from_raw_parts_mut};
use lazy_static::lazy_static;
use scroll::{Pread, Pwrite};
use spin::Mutex;

use crate::tdx;

pub const TD_REPORT_SIZE: usize = 0x400;
pub const TD_REPORT_ADDITIONAL_DATA_SIZE: usize = 64;

// The buffer to td_report() must be aligned to TD_REPORT_SIZE.
const TD_REPORT_BUFF_SIZE: usize = (TD_REPORT_SIZE * 2) + TD_REPORT_ADDITIONAL_DATA_SIZE;

#[repr(C)]
#[derive(Debug, Pread, Pwrite)]
pub struct ReportType {
    pub r#type: u8,
    pub subtype: u8,
    pub version: u8,
    pub reserved: u8,
}

#[repr(C)]
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

#[repr(C)]
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

#[repr(C)]
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
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { &mut *slice_from_raw_parts_mut(self as *mut Self as *mut u8, size_of::<Self>()) }
    }
}

struct TdxReportBuf {
    buf: [u8; TD_REPORT_BUFF_SIZE],
    offset: usize,
    end: usize,
    additional: usize,
}

impl TdxReportBuf {
    fn new() -> Self {
        let mut buf = TdxReportBuf {
            buf: [0u8; TD_REPORT_BUFF_SIZE],
            offset: 0,
            end: 0,
            additional: 0,
        };
        let pos = buf.buf.as_ptr() as *const u8 as usize;

        buf.offset = TD_REPORT_SIZE - (pos & (TD_REPORT_SIZE - 1));
        buf.end = buf.offset + TD_REPORT_SIZE;
        buf.additional = buf.end + TD_REPORT_ADDITIONAL_DATA_SIZE;

        buf
    }

    fn report_buf_start(&mut self) -> u64 {
        &mut self.buf[self.offset] as *mut u8 as u64
    }

    fn additional_buf_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.end..self.additional]
    }

    fn to_owned(&self) -> TdxReport {
        let mut report: TdxReport = TdxReport::default();
        report
            .as_bytes_mut()
            .copy_from_slice(&self.buf[self.offset..self.end]);
        report
    }
}

impl Default for TdxReport {
    fn default() -> Self {
        unsafe { zeroed() }
    }
}

lazy_static! {
    static ref TD_REPORT: Mutex<TdxReportBuf> = Mutex::new(TdxReportBuf::new());
}

/// Query TDX report information.
pub fn tdcall_report(additional_data: &[u8; TD_REPORT_ADDITIONAL_DATA_SIZE]) -> TdxReport {
    let mut buff = TD_REPORT.lock();
    let addr = buff.report_buf_start();

    buff.additional_buf_mut().copy_from_slice(additional_data);
    let ret = unsafe {
        tdx::td_call(
            tdx::TDCALL_TDREPORT,
            addr,
            addr + TD_REPORT_SIZE as u64,
            0,
            0,
        )
    };
    if ret != tdx::TDX_EXIT_REASON_SUCCESS {
        tdx::tdvmcall_halt();
    }

    buff.to_owned()
}

/// Dump TDX report information.
pub fn tdreport_dump() {
    let addtional_data: [u8; 64] = [0; 64];
    let tdx_report = tdcall_report(&addtional_data);
    log::info!("{}", tdx_report);
}
