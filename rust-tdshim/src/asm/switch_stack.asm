# Copyright (c) 2020 Intel Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent

.section .text

#  switch_stack_call(
#       entry_point: usize, // rcx
#       stack_top: usize,   // rdx
#       P1: usize,          // r8
#       P2: usize           // r9
#       );
.global switch_stack_call
switch_stack_call:
        sub    rdx,0x20
        mov    rsp,rdx
        mov    rax,rcx
        mov    rcx,r8
        mov    rdx,r9
        call   rax
        int3
        jmp    switch_stack_call
        ret
