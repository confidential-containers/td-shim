# Copyright (c) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent

.section .text

#  cet_ss_test(
#       loop: usize,  // rcx
#       );
.global cet_ss_test
cet_ss_test:
        mov rdx, rsp
rcx_test:
        cmp rcx, 0x1000
        jnz rcx_test
write_stack:
        mov byte ptr [rdx], 100
        add rdx, 1
        dec rcx
        jnz write_stack

        ret
