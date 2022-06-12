# Copyright (c) 2020 Intel Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent

.section .text

#  switch_stack_call_win64(
#       entry_point: usize, // rcx
#       stack_top: usize,   // rdx
#       P1: usize,          // r8
#       P2: usize           // r9
#       );
.global switch_stack_call_win64
switch_stack_call_win64:
        sub    rdx,0x20
        mov    rsp,rdx
        mov    rax,rcx
        mov    rcx,r8
        mov    rdx,r9
        call   rax
        int3
        jmp    switch_stack_call_win64
        ret

#  switch_stack_call_sysv(
#       entry_point: usize, // rcx
#       stack_top: usize,   // rdx
#       P1: usize,          // r8
#       P2: usize           // r9
#       );
.global switch_stack_call_sysv
switch_stack_call_sysv:
        sub    rdx,0x20
        mov    rsp,rdx
        mov    rax,rcx
        mov    rdi,r8
        mov    rsi,r9
        call   rax
        int3
        jmp    switch_stack_call_sysv
        ret
