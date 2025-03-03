// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::*;

// GTDG.VP.VMCALL leaf sub-function numbers
const TDVMCALL_CPUID: u64 = 0x0000a;
const TDVMCALL_HALT: u64 = 0x0000c;
const TDVMCALL_IO: u64 = 0x0001e;
const TDVMCALL_RDMSR: u64 = 0x0001f;
const TDVMCALL_WRMSR: u64 = 0x00020;
const TDVMCALL_MMIO: u64 = 0x00030;
const TDVMCALL_MAPGPA: u64 = 0x10001;
const TDVMCALL_GETQUOTE: u64 = 0x10002;
const TDVMCALL_SETUPEVENTNOTIFY: u64 = 0x10004;
const TDVMCALL_SERVICE: u64 = 0x10005;

// TDVMCALL completion status code
const TDVMCALL_STATUS_SUCCESS: u64 = 0;
const TDVMCALL_STATUS_RETRY: u64 = 1;

// Used to pass the values of input/output register when performing TDVMCALL
// instruction
#[repr(C)]
#[derive(Default)]
pub struct TdVmcallArgs {
    // Input: Always 0 for  (standard VMCALL)
    // Output: Sub-function
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

/// TDVMCALL sub-function return error code
///
/// Refer to Guest-Host-Communication-Interface(GHCI) for Intel TDX
/// table 'TDCALL[TDG.VP.VMCALL]- Sub-function Completion-Status Codes'
#[derive(Debug, PartialEq)]
pub enum TdVmcallError {
    // TDCALL[TDG.VP.VMCALL] sub-function invocation must be retried
    VmcallRetry,

    // Invalid operand to TDG.VP.VMCALL sub-function
    VmcallOperandInvalid,

    // GPA already mapped
    VmcallGpaInuse,

    // Operand (address) alignment error
    VmcallAlignError,

    Other,
}

impl From<u64> for TdVmcallError {
    fn from(val: u64) -> Self {
        match val {
            0x1 => TdVmcallError::VmcallRetry,
            0x8000_0000_0000_0000 => TdVmcallError::VmcallOperandInvalid,
            0x8000_0000_0000_0001 => TdVmcallError::VmcallGpaInuse,
            0x8000_0000_0000_0002 => TdVmcallError::VmcallAlignError,
            _ => TdVmcallError::Other,
        }
    }
}

// A public wrapper for use of asm_td_vmcall, this function takes a mutable reference of a
// TdcallArgs structure to ensure the input is valid
//
// ## TDVMCALL ABI
// Defined in GHCI Spec section 'TDCALL [TDG.VP.VMCALL] leaf'
//
// ### Input Operands:
// * RAX - TDCALL instruction leaf number (0 - TDG.VP.VMCALL)
// * RCX - A bitmap that controls which part of guest TD GPR is exposed to VMM.
// * R10 - Set to 0 indicates leaf-function used in R11 is defined in standard GHCI Spec.
// * R11 - TDG.VP.VMCALL sub-function is R10 is zero
// * RBX, RBP, RDI, RSI, R8-R10, R12-R15 - Used to pass values to VMM in sub-functions.
//
// ### Output Operands:
// * RAX - TDCALL instruction return code, always return Success(0).
// * R10 - TDG.VP.VMCALL sub-function return value
// * R11 - Correspond to each TDG.VP.VMCALL.
// * R8-R9, R12-R15, RBX, RBP, RDI, RSI - Correspond to each TDG.VP.VMCALL sub-function.
//
pub fn td_vmcall(args: &mut TdVmcallArgs) -> u64 {
    unsafe { asm::asm_td_vmcall(args as *mut TdVmcallArgs as *mut c_void, 0) }
}
