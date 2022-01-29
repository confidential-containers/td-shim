# Copyright (c) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent

.section .text
#  stack_guard_test(
#       );
.global stack_guard_test
stack_guard_test:

loop:
    push rax
    jmp loop
