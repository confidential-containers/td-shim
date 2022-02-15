// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate scroll;

pub mod elf;
pub mod elf64;
pub mod pe;
