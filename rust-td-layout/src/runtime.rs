// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

/*
    Mem Layout:
                                            Address
                    +--------------+ <-  0x0
                    |     Legacy   |
                    +--------------+ <-  0x00100000 (1M)
                    |   ........   |
                    +--------------+ <-  0x00800000
                    |  Page Table  |
                    +--------------+ <-  0x01000000
                    | PAYLOAD PARAM|    (0x00100000)
                    +--------------+ <-  0x01100000
                    |    PAYLOAD   |    (0x02000000)
                    +--------------+
                    |   ........   |
                    +--------------+ <-  0x7D000000
                    |     DMA      |    (0x01000000)
                    +--------------+ <-  0x7E000000
                    |     HEAP     |    (0x01000000)
                    +--------------+ <-  0x7F000000
                    |     STACK    |    (0x00800000)
                    +--------------+ <-  0x7F800000
                    |      SS      |    (0x00200000)
                    +--------------+ <-  0x7FA00000
                    |    TD_HOB    |    (0x00400000)
                    +--------------+ <-  0x7FE00000
                    |     ACPI     |    (0x00100000)
                    +--------------+ <-  0x7FF00000
                    | TD_EVENT_LOG |    (0x00100000)
                    +--------------+ <-  0x80000000 (2G) - for example
*/

pub const TD_PAYLOAD_EVENT_LOG_SIZE: u32 = 0x100000;
pub const TD_PAYLOAD_ACPI_SIZE: u32 = 0x100000;
pub const TD_PAYLOAD_HOB_SIZE: u32 = 0x400000;
pub const TD_PAYLOAD_SHADOW_STACK_SIZE: u32 = 0x200000;
pub const TD_PAYLOAD_STACK_SIZE: u32 = 0x800000;
pub const TD_PAYLOAD_HEAP_SIZE: usize = 0x1000000;
pub const TD_PAYLOAD_DMA_SIZE: usize = 0x1000000;

pub const TD_PAYLOAD_PAGE_TABLE_BASE: u64 = 0x800000;
pub const TD_PAYLOAD_PARAM_BASE: u64 = 0x1000000;
pub const TD_PAYLOAD_PARAM_SIZE: u64 = 0x100000;
pub const TD_PAYLOAD_BASE: u64 = 0x1100000;
pub const TD_PAYLOAD_SIZE: usize = 0x2000000;
