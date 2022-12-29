// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! This crate provides heap profiling and stack profiling capabilities
//! only for TD environment.
//!
//! # Features
//! - benchmark this features enabled by default.
//!   with this feature enabled, the customer `ALLOCATOR` is
//!   registered to `#[global_allocator]` automatic. It can
//!   be disabled by adding `--default-features = false`.
//!
//! # Stack usage testing
//!
//! `StackProfiling` provide functions for stack usage testing
//!
//! # Example
//!
//! ```no_run
//! use td_benchmark::StackProfiling;
//! StackProfiling::init(0x5a5a_5a5a_5a5a_5a5a, 0x1A0000);
//!
//! {
//!     let a = [0;1024];
//!     // insert calls like this at the point of interest.
//!     let stack_usage = StackProfiling::stack_usage().unwrap();
//! }
//! ```
//!
//! # Heap usage testing
//!
//! `HeapProfiling` provide functions for stack usage testing
//!
//! Use `HeapProfiling` need disable `benchmark` feature by adding `default-features = false`
//! For example in Cargo.toml:
//!
//! td-benchmark = { path = "path_to/td-shim/devtools/td-benchmark", default-features = false, optional = true}
//!
//! ```no_std
//! // adding global allocator `Alloc`
//! #[global_allocator]
//! static ALLOC: td_benchmark::Alloc = td_benchmark::Alloc;
//!
//! // Then add the following code to your code to initialize alloc before allocation.
//! // heap start heap end is the location where the heap is created.
//! HeapProfiling::init(heap_start, heap_size);
//!
//!
//! // call `heap_usage` at the point your interest.
//! let stack_usage = HeapProfiling::heap_usage().unwrap();
//! ```
//!
#![no_std]

extern crate alloc;

mod heap;
mod stack;

pub use heap::{Alloc, HeapProfiling};
pub use stack::StackProfiling;
