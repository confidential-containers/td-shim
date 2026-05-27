# td-paging

A simple `no_std` x86_64 page table manager for the [td-shim](https://github.com/confidential-containers/td-shim) Intel TDX Confidential Computing shim. It provides physical-to-virtual address mapping via multi-level page tables (4K/2M/1G page sizes), a bitmap-based physical frame allocator for page table pages, and a small API for initializing mappings and writing `CR3`. The crate requires an allocator and uses identity mapping by default (`PHYS_VIRT_OFFSET = 0`).

## Key Types and Functions

### Public API (`lib.rs`)

| Symbol | Description |
|--------|-------------|
| `init(base, size)` | Initialize the frame allocator with a page-aligned physical memory region for page table pages. Must be called before any mapping. |
| `reserve_page(addr)` | Mark a specific physical page as already in use (prevents it from being allocated for page table pages). |
| `create_mapping(pt, pa, va, ps, sz)` | Map `[va, va+sz)` → `[pa, pa+sz)` using default flags (`PRESENT | WRITABLE`). |
| `create_mapping_with_flags(pt, pa, va, ps, sz, flags)` | Same as above with explicit `PageTableFlags`. |
| `set_page_flags(pt, va, sz, set, clear)` | Update flags on an existing mapping without remapping. |
| `cr3_write(addr)` | Write the physical address of the PML4 table to `CR3`. |

### Internal Types

- **`BMFrameAllocator`** (`frame.rs`) — Bitmap-based frame allocator backed by a contiguous physical region.
  Implements `x86_64::FrameAllocator<Size4KiB>`.
  Exposed via the global `FRAME_ALLOCATOR` mutex.

### Constants (`consts.rs`)

| Constant | Value | Description |
|----------|-------|-------------|
| `PHYS_VIRT_OFFSET` | `0` | Physical-to-virtual offset (identity mapping) |
| `PAGE_SIZE` | `0x1000` | 4 KiB page size |
| `PAGE_SIZE_4K` | `0x1000` | Explicit 4K PTE size |
| `PAGE_SIZE_DEFAULT` | `0x4000_0000` | Default PTE size (1 GiB) |

## Usage Notes

1. Call `init(base, size)` once at startup, passing a page-aligned region large enough to hold all page table pages the shim will need.
2. Optionally call `reserve_page(addr)` for any pages within that region that are already in use.
3. Build an `x86_64::OffsetPageTable`, then call `create_mapping` or `create_mapping_with_flags` to establish mappings.
4. Call `cr3_write` with the physical address of your PML4 to activate the page table.

Supported page granularities: **4 KiB**, **2 MiB**, **1 GiB**.
The `ps` parameter to `create_mapping*` selects the granularity; mappings are automatically split or promoted based on alignment and size.
