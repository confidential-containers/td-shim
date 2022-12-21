# Copyright (c) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent

.set TDVMCALL_EXPOSE_REGS_MASK,           0xfc00
.set TDVMCALL,                            0x0
.set INSTRUCTION_HLT,                     0xc

.section .text

#--------------------------------------------------------------------
# empty_exception_handler
#
# We do not need to save the context here because this function will
# never return.
#--------------------------------------------------------------------
.global empty_exception_handler
empty_exception_handler:
    mov         rax, TDVMCALL
    mov         rcx, TDVMCALL_EXPOSE_REGS_MASK
    mov         r10, 0
    mov         r11, INSTRUCTION_HLT
    mov         r12, 0
    mov         r13, 0
    mov         r14, 0
    mov         r15, 0
    # TDVMCALL
    .byte       0x66, 0x0f, 0x01, 0xcc
.exception_loop:
    jmp         .exception_loop

.global empty_exception_handler_end
empty_exception_handler_end:
    jmp         .exception_loop
