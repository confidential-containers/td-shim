# Copyright (c) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent

.section .text
#  asm_read_msr64(
#       index: u32, // rcx
#       );
.global asm_read_msr64
asm_read_msr64:

    rdmsr
    shl rdx, 0x20
    or  rax, rdx
    ret

#  asm_write_msr64(
#       index: u32, // rcx
#       value: u64, // rdx
#       );
.global asm_write_msr64
asm_write_msr64:

    mov rax, rdx
    shr rdx, 0x20
    wrmsr
    ret
