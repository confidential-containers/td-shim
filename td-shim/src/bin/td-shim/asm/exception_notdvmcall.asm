# Copyright (c) 2022, 2025 Intel Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent

.section .text

#--------------------------------------------------------------------
# empty_exception_handler
#
# We do not need to save the context here because this function will
# never return.
#--------------------------------------------------------------------
.global empty_exception_handler
empty_exception_handler:
    hlt
.exception_loop:
    jmp         .exception_loop

.global empty_exception_handler_end
empty_exception_handler_end:
    jmp         .exception_loop
