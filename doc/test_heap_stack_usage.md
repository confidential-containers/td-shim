## Test runtime heap and stack usage.

### td-benchmark framework structure.

Feature `benchmark` is enabled by default. The `benchmark` feature is added to be compatible with those codes that use benchmarks code.

All code for testing heap and stack are located in [dev/tools/td-benchmark](../devtools/td-benchmark).

[heap.rs](../devtools/td-benchmark/src/heap.rs) provide a global allocator which contains a function to obtain heap usage size.

[stack.rs](../devtools/td-benchmark/src/stack.rs) provide functions to get the stack usage size.

### How to test heap and stack usage library.

0. Add `td-benchmark` crate into `Cargo.toml`. For example:
   ```Cargo.toml
   td-benchmark = { path = "devtools/td-benchmark", default-features = false}
   ```

### How to get runtime heap usage.

1. Register `td_benchmark:Alloc` as global allocator

   ```
   #[global_allocator]
   static ALLOC: td_benchmark::Alloc = td_benchmark::Alloc;
   ```

2. `global_allocator` must be initialized before using heap.
   ```
   HeapProfiling::init(heap_start, heap_size);
   ```

3. Call `heap_usage` at the point you interest.
   ```
   let stack_usage = HeapProfiling::heap_usage().unwrap();
   ```

### How to get runtime stack usage.

1. Mark stack with special mark value.

   ```
   StackProfiling::init(0x5a5a_5a5a_5a5a_5a5a, 0x1A0000);
   ```
   Note: Stack size should be choose carefully.

2. Get stack usage at the point you interest.
   ```
   let stack_usage = StackProfiling::stack_usage().unwrap();
   ```

### Limitation

This method is limited by execution coverage. If some functions are not reached at runtime, then no data is collected.
