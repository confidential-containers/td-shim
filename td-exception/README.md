# td-exception

Sets up and manages the x86_64 Interrupt Descriptor Table (IDT) for `td-shim`, initializing a stub IDT that handles all 256 exception and interrupt vectors. It operates under the assumption of identity-mapped (1:1 physical-to-virtual) address space. When the `tdx` feature is enabled, it also handles the Virtualization Exception (#VE, vector 20) via `tdx-tdcall`.

Interrupt handlers are implemented in assembly (`handler.asm`) and dispatch to a Rust-level callback table, allowing callers to register custom handlers per vector at runtime.

## Key Types and Functions

### `lib.rs`

- **`setup_exception_handlers()`** — Top-level entry point.
  Initializes the IDT and loads it via `lidt`.
  Call this once at boot.
- **`ExceptionError`** — Error type returned by callback registration.

### `idt` module

- **`Idt`** — Owns the 256-entry IDT.
  Initialized with stub entries pointing into the assembly handler table.
- **`IdtEntry`** — A single 16-byte x86_64 IDT gate descriptor.
- **`IdtFlags`** — Bitflags for gate attributes (present, ring level, interrupt/trap type).
- **`init()`** — Unsafe; constructs and loads the global IDT.
- **`register_handler(index, func)`** — Unsafe; replaces the raw ASM handler for a specific vector and reloads the IDT.

### `interrupt` module

- **`InterruptStack`** — Packed struct representing the full CPU state on the stack when an interrupt fires (preserved registers, scratch registers, vector number, error code, IRET frame).
- **`ScratchRegisters` / `PreservedRegisters` / `IretRegisters`** — Sub-structures of `InterruptStack` with `.dump()` helpers for logging.
- **`InterruptCallback`** — A function pointer wrapper (`fn(&mut InterruptStack)`) stored in the callback table.
- **`register_interrupt_callback(index, callback)`** — Registers a Rust-level callback for a given vector (0–255).
  Safe to call after `setup_exception_handlers()`.

## Default Exception Handlers

Vectors 0–21 are pre-wired to named handlers (e.g. `divide_by_zero`, `page`, `protection`, `virtualization`).
All others fall through to `default_callback`, which logs the vector and register state.

## Cargo Features

| Feature | Effect |
|---|---|
| `tdx` | Enables `#VE` (vector 20) handling via `tdx-tdcall` |
| `no-interrupt` | Only sets up exception vectors (0–31); vectors 32–255 are left non-present, causing `#GP` on unexpected VMM interrupts |
| `no-tdvmcall` | Passes through to `tdx-tdcall/no-tdvmcall` |
| `cet-shstk` | Enables CET shadow stack support |
| `integration-test` | Exposes `DIVIDED_BY_ZERO_EVENT_COUNT` atomic counter for testing |

## Usage

```rust
// At boot, after setting up the GDT:
td_exception::setup_exception_handlers();

// Optionally register a custom handler for a specific vector:
use td_exception::interrupt::{InterruptCallback, InterruptStack};

fn my_handler(stack: &mut InterruptStack) {
    stack.dump();
}

td_exception::interrupt::register_interrupt_callback(
    14, // #PF
    InterruptCallback::new(my_handler),
).unwrap();
```
