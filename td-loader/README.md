# td-loader

A `no_std` parser and loader for 64-bit Portable Executable (PE+) and 32/64-bit ELF binary objects, used within the [td-shim](https://github.com/confidential-containers/td-shim) Confidential Computing shim for Intel TDX. It parses and relocates images into a caller-supplied memory buffer and contains no unsafe code.

Relocation support:
- **ELF**: applies `R_X86_64_RELATIVE` relocations per program header
- **PE+** (PE32+, x86-64 only): applies base relocations (`REL_BASED_DIR64`) per section

## Modules

| Module | Description |
|--------|-------------|
| `elf`   | High-level ELF loading: image detection, relocation, and init-array section parsing |
| `elf64` | Low-level ELF64 structure definitions and parser (`Elf`, `ProgramHeader`, `Rela`, etc.) |
| `pe`    | PE32+ image detection and relocation |

## Key Functions

### `elf`

```rust
/// Returns true if the byte slice begins with the ELF magic bytes.
pub fn is_elf(image: &[u8]) -> bool

/// Relocates an ELF image into `loaded_buffer` using the buffer's own address as the new base.
/// Returns `(entry_point, image_bottom, image_top)` on success.
pub fn relocate_elf_mem_with_per_program_header(
    image: &[u8],
    loaded_buffer: &mut [u8],
) -> Option<(u64, u64, u64)>

/// Relocates an ELF image into `loaded_buffer` at an explicit `new_image_base`.
pub fn relocate_elf_with_per_program_header(
    image: &[u8],
    loaded_buffer: &mut [u8],
    new_image_base: usize,
) -> Option<(u64, u64, u64)>

/// Returns the byte range of `.preinit_array`, `.init_array`, or `.fini_array`
/// within an already-loaded image.
pub fn parse_pre_init_array_section(loaded_image: &[u8]) -> Option<Range<usize>>
pub fn parse_init_array_section(loaded_image: &[u8]) -> Option<Range<usize>>
pub fn parse_finit_array_section(loaded_image: &[u8]) -> Option<Range<usize>>
```

### `pe`

```rust
/// Returns true if the byte slice is a valid x86-64 PE32+ image.
pub fn is_x86_64_pe(pe_image: &[u8]) -> bool

/// Relocates a PE image into `new_pe_image` at `new_image_base`.
/// Returns the entry point offset on success.
pub fn relocate(pe_image: &[u8], new_pe_image: &mut [u8], new_image_base: usize) -> Option<usize>

/// Relocates a PE image per-section into `new_pe_image` using the buffer's own address as base.
pub fn relocate_pe_mem_with_per_sections(
    pe_image: &[u8],
    new_pe_image: &mut [u8],
) -> Option<usize>

/// Relocates a PE image per-section at an explicit `new_image_base`.
pub fn relocate_with_per_section(
    pe_image: &[u8],
    new_pe_image: &mut [u8],
    new_image_base: usize,
) -> Option<usize>
```

## Usage Notes

- The crate is `no_std` (except when compiled with `cfg(test)`).
- All public APIs return `Option` — `None` indicates a malformed or unsupported image.
- The caller is responsible for allocating `loaded_buffer` / `new_pe_image` with sufficient size before calling any relocation function.
- Only x86-64 targets are supported for both ELF (`R_X86_64_RELATIVE`) and PE+ (`MACHINE_X64`).
