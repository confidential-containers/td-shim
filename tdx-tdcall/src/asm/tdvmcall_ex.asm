# Copyright (c) 2020-2025 Intel Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent

.section .text

# Mask used to control which part of the guest TD GPR and XMM
# state is exposed to the VMM. A bit value of 1 indicates the
# corresponding register is passed to VMM. Refer to TDX Module
# ABI specification section TDG.VP.VMCALL for detail.
# Here we expose RDX, RBX, RSI, RDI, R8 - R15 to VMM in td_vm_call_ex()
.equ TDVMCALL_EXPOSE_REGS_MASK, 0xffcc

# TDG.VP.VMCALL leaf number
.equ TDVMCALL, 0

# Arguments offsets in TdVmcallArgsEx struct
.equ VMCALL_ARG_RDX, 0x0
.equ VMCALL_ARG_RBX, 0x8
.equ VMCALL_ARG_RSI, 0x10
.equ VMCALL_ARG_RDI, 0x18
.equ VMCALL_ARG_R8, 0x20
.equ VMCALL_ARG_R9, 0x28
.equ VMCALL_ARG_R10, 0x30
.equ VMCALL_ARG_R11, 0x38
.equ VMCALL_ARG_R12, 0x40
.equ VMCALL_ARG_R13, 0x48
.equ VMCALL_ARG_R14, 0x50
.equ VMCALL_ARG_R15, 0x58

# asm_td_vmcall_ex -> u64 (
#   args: *mut TdVmcallArgsEx,
#   do_sti: u64,
# )
.global asm_td_vmcall_ex
asm_td_vmcall_ex:
        endbr64
        # Save the registers according to MS x64 calling convention
        push rbp
        mov rbp, rsp
        push r15
        push r14
        push r13
        push r12
        push rbx
        push rsi
        push rdi

        # Test if input pointer is valid
        test rcx, rcx
        jz vmcall_ex_exit

        # Copy the input operands from memory to registers
        mov rbx, [rcx + VMCALL_ARG_RBX]
        mov rsi, [rcx + VMCALL_ARG_RSI]
        mov rdi, [rcx + VMCALL_ARG_RDI]
        mov r8, [rcx + VMCALL_ARG_R8]
        mov r9, [rcx + VMCALL_ARG_R9]
        mov r10, [rcx + VMCALL_ARG_R10]
        mov r11, [rcx + VMCALL_ARG_R11]
        mov r12, [rcx + VMCALL_ARG_R12]
        mov r13, [rcx + VMCALL_ARG_R13]
        mov r14, [rcx + VMCALL_ARG_R14]
        mov r15, [rcx + VMCALL_ARG_R15]
        # Set TDCALL leaf number
        mov rax, TDVMCALL

        # Save TdVmcallArgsEx pointer to stack since no registers are available
        push rcx

        # Test if the `sti` is needed
        test rdx, rdx
        jnz .Ldo_tdcall_sti

        # Copy the RDX input operand from memory to register
        mov rdx, [rcx + VMCALL_ARG_RDX]
        # Set exposed register mask
        mov ecx, TDVMCALL_EXPOSE_REGS_MASK
        jmp .Ldo_tdcall_ex

.Ldo_tdcall_sti:
        # Copy the RDX input operand from memory to register
        mov rdx, [rcx + VMCALL_ARG_RDX]
        # Set exposed register mask
        mov ecx, TDVMCALL_EXPOSE_REGS_MASK
        sti

.Ldo_tdcall_ex:
        # TDCALL
       .byte 0x66,0x0f,0x01,0xcc

        # RAX should always be zero for TDVMCALL, panic if it is not.
        test rax, rax
        jnz vmcall_ex_panic

        # Restore TdVmcallArgsEx pointer
        pop rcx

        # Copy the output operands from registers to the struct
        mov [rcx + VMCALL_ARG_RDX], rdx
        mov [rcx + VMCALL_ARG_RBX], rbx
        mov [rcx + VMCALL_ARG_RSI], rsi
        mov [rcx + VMCALL_ARG_RDI], rdi
        mov [rcx + VMCALL_ARG_R8], r8
        mov [rcx + VMCALL_ARG_R9], r9
        mov [rcx + VMCALL_ARG_R10], r10
        mov [rcx + VMCALL_ARG_R11], r11
        mov [rcx + VMCALL_ARG_R12], r12
        mov [rcx + VMCALL_ARG_R13], r13
        mov [rcx + VMCALL_ARG_R14], r14
        mov [rcx + VMCALL_ARG_R15], r15

        mov rax, r10

vmcall_ex_exit:
        # Clean the registers that are exposed to VMM to
        # protect against speculative attack, others will
        # be restored to the values saved in stack
        xor rdx, rdx
        xor r8, r8
        xor r9, r9
        xor r10, r10
        xor r11, r11

        # Pop out saved registers from stack
        pop rdi
        pop rsi
        pop rbx
        pop r12
        pop r13
        pop r14
        pop r15
        pop rbp

        ret

vmcall_ex_panic:
        ud2
