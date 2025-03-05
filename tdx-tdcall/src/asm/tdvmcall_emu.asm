# Copyright (c) 2020 Intel Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent

.section .text

.equ USE_TDX_EMULATION, 1
.equ TDVMCALL_EXPOSE_REGS_MASK,       0xffec
.equ TDVMCALL,                        0x0
.equ EXIT_REASON_CPUID,               0xa

.equ number_of_regs_pushed, 8
.equ number_of_parameters,  4

.equ first_variable_on_stack_offset,   (number_of_regs_pushed * 8) + (number_of_parameters * 8) + 8
.equ second_variable_on_stack_offset,  first_variable_on_stack_offset + 8

#  UINT64
#  TdVmCall (
#    UINT64  Leaf,
#    UINT64  P1,
#    UINT64  P2,
#    UINT64  P3,
#    UINT64  P4,
#    UINT64  *Val
#    )
.global td_vm_call
td_vm_call:
        endbr64
        # tdcall_push_regs
        push rbp
        mov  rbp, rsp
        push r15
        push r14
        push r13
        push r12
        push rbx
        push rsi
        push rdi

        mov  r11, rcx
        mov  r12, rdx
        mov  r13, r8
        mov  r14, r9
        mov  r15, [rsp+first_variable_on_stack_offset]

       #tdcall_regs_preamble TDVMCALL, TDVMCALL_EXPOSE_REGS_MASK
        mov rax, TDVMCALL

        mov ecx, TDVMCALL_EXPOSE_REGS_MASK

        # R10 = 0 (standard TDVMCALL)

        xor r10d, r10d

        # Zero out unused (for standard TDVMCALL) registers to avoid leaking
        # secrets to the VMM.

        xor ebx, ebx
        xor esi, esi
        xor edi, edi

        xor edx, edx
        xor ebp, ebp
        xor r8d, r8d
        xor r9d, r9d

       # tdcall
       .if USE_TDX_EMULATION != 0
       vmcall
       .else
       .byte 0x66,0x0f,0x01,0xcc
       .endif

       # ignore return dataif TDCALL reports failure.
       test rax, rax
       jnz no_return_data

       # Propagate TDVMCALL success/failure to return value.
       mov rax, r10

       # Retrieve the Val pointer.
       mov r9, [rsp+second_variable_on_stack_offset]
       test r9, r9
       jz no_return_data

       # On success, propagate TDVMCALL output value to output param
       test rax, rax
       jnz no_return_data
       mov [r9], r11

no_return_data:
        #tdcall_regs_postamble
        xor ebx, ebx
        xor esi, esi
        xor edi, edi

        xor ecx, ecx
        xor edx, edx
        xor r8d, r8d
        xor r9d, r9d
        xor r10d, r10d
        xor r11d, r11d

        # tdcall_pop_regs
        pop rdi
        pop rsi
        pop rbx
        pop r12
        pop r13
        pop r14
        pop r15
        pop rbp

       ret
