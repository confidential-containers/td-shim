# Changelog
All notable changes to this project will be documented in this file.

## [0.2.1] - 2024-07-23
### Changed
- Remove nightly feature in the x86_64 crate
- Fix TdCallError parsing

## [0.2.0] - 2024-06-21
### Added
- Wrapper to tdcall_accept_page to accept a memory range (for both normal 4K as well as 2M large pages).
- Add tdcall_vm_read/write to access TD-scope meta field of a TD.
- Add tdcall_vp_read/write is to access vCPU-scope meta field of a TD.
- Add tdcall_vp_invept/invvpid to provide SEPT flushing support.
- Add tdcall_vp_enter support.
- Add tdcall to support memory attribute write.

### Changed
- Change return type for tdvmcall::wrmsr, tdvmcall::rdmsr
- Replace the & operator with addr_of! macro for tdvmcall::mmio_write/tdvmcall::mmio_read
- Extend TdInfo struct to add vcpu_index field

## [0.1.0] - 2024-06-07
### Added
- Add README.md for publishing to crates.io
