# td-benchmark

A lightweight library for heap and stack profiling in bare-metal / `no_std` Trust Domain (TD) environments such as the TD-Shim firmware. Intended for development and debugging rather than production use.

## Key Types

### `StackProfiling`

Profiles stack usage by filling a region of the stack with a magic marker value, then scanning for the high-water mark after a region of interest executes.

```rust
use td_benchmark::StackProfiling;

// Fill 0x1A0000 bytes below the current stack pointer with the marker value.
StackProfiling::init(0x5a5a_5a5a_5a5a_5a5a, 0x1A0000);

// ... code under test ...

let stack_usage = StackProfiling::stack_usage().unwrap();
```

### `HeapProfiling`

Tracks peak heap allocation by wrapping the `linked_list_allocator` allocator and recording the running maximum of bytes in use.

### `Alloc`

A `GlobalAlloc`-implementing type that instruments every allocation/deallocation to maintain the peak usage counter used by `HeapProfiling`.

## Usage Notes

### Default feature (`benchmark`)

When the `benchmark` feature is enabled (the default), a custom global allocator backed by `Alloc` is registered automatically.
Use `HeapProfiling::init(heap_start, heap_size)` to initialise the heap before any allocation, then call `HeapProfiling::heap_usage()` to retrieve the peak bytes used.

### Disabling the default feature

To use your own `#[global_allocator]` alongside `HeapProfiling`, disable the default feature and register `Alloc` explicitly:

```toml
# Cargo.toml
td-benchmark = { path = "...", default-features = false, optional = true }
```

```rust
#[global_allocator]
static ALLOC: td_benchmark::Alloc = td_benchmark::Alloc;

HeapProfiling::init(heap_start, heap_size);
// ... allocations ...
let peak = HeapProfiling::heap_usage().unwrap();
```

## Dependencies

| Crate | Purpose |
|---|---|
| `linked_list_allocator` | Underlying heap allocator |
| `lazy_static` + `spin` | Interrupt-safe global state |
| `x86` / `td-layout` | Optional, for TD-specific integration |
