# Copyright (c) 2024 Intel Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent

# Mask the exception vectors that push an error code on the stack
.equ EXCEPTION_ERROR_CODE_MASK, 0x20027d00

.section .text
interrupt_handler_entry:
        push rax
        push rcx
        push rdx
        push rdi
        push rsi
        push r8
        push r9
        push r10
        push r11
        push rbx
        push rbp
        push r12
        push r13
        push r14
        push r15

        mov rdi, rsp
        call generic_interrupt_handler

        pop r15
        pop r14
        pop r13
        pop r12
        pop rbp
        pop rbx
        pop r11
        pop r10
        pop r9
        pop r8
        pop rsi
        pop rdi
        pop rdx
        pop rcx
        pop rax

        # vector number and error code
        add rsp, 16

        iretq

.align 32
.global interrupt_handler_table
interrupt_handler_table:
        i = 0
        .rept 256
        .align 32
        .if ((EXCEPTION_ERROR_CODE_MASK >> i) & 1) == 0
        push 0
        .endif
        push i
        jmp interrupt_handler_entry
        i = i + 1
        .endr

        ret
