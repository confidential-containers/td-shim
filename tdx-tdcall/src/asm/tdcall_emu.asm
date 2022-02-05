# Copyright (c) 2020 Intel Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent

.section .text
.equ USE_TDX_EMULATION, 1
.equ number_of_regs_pushed, 8
.equ number_of_parameters,  4

.equ first_variable_on_stack_offset,   (number_of_regs_pushed * 8) + (number_of_parameters * 8) + 8
.equ second_variable_on_stack_offset,  first_variable_on_stack_offset + 8

#  TdCall (
#    UINT64  Leaf,
#    UINT64  P1,
#    UINT64  P2,
#    UINT64  P3,
#    UINT64  Results,
#    )
.global td_call
td_call:
        # tdcall_push_regs
        push rbp
        mov rbp, rsp
        push r15
        push r14
        push r13
        push r12
        push rbx
        push rsi
        push rdi

       mov rax, rcx
       mov rcx, rdx
       mov rdx, r8
       mov r8, r9

       # tdcall
       .if USE_TDX_EMULATION != 0
       vmcall
       .else
       .byte 0x66,0x0f,0x01,0xcc
       .endif

       # exit if tdcall reports failure.
       test rax, rax
       jnz exit

       # test if caller wanted results
       mov  r12, [rsp + first_variable_on_stack_offset]
       test r12, r12
       jz exit
       mov [r12], rcx
       mov [r12+8], rdx
       mov [r12+16], r8
       mov [r12+24], r9
       mov [r12+32], r10
       mov [r12+40], r11
exit:
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
