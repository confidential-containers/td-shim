// Copyright © 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use r_efi::efi::{Guid, PhysicalAddress};
use scroll::{Pread, Pwrite};

use super::boot_mode::BootMode;

pub const HOB_LIST_GUID: Guid = Guid::from_fields(
    0x7739F24C,
    0x93D7,
    0x11D4,
    0x9A,
    0x3A,
    &[0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D],
);

pub type ResourceType = u32;

pub const RESOURCE_SYSTEM_MEMORY: u32 = 0x00;
pub const RESOURCE_MEMORY_MAPPED_IO: u32 = 0x01;
pub const RESOURCE_IO: u32 = 0x02;
pub const RESOURCE_FIRMWARE_DEVICE: u32 = 0x03;
pub const RESOURCE_MEMORY_MAPPED_IO_PORT: u32 = 0x04;
pub const RESOURCE_MEMORY_RESERVED: u32 = 0x05;
pub const RESOURCE_IO_RESERVED: u32 = 0x06;

pub type ResourceAttributeType = u32;

pub const RESOURCE_ATTRIBUTE_PRESENT: u32 = 0x00000001;
pub const RESOURCE_ATTRIBUTE_INITIALIZED: u32 = 0x00000002;
pub const RESOURCE_ATTRIBUTE_TESTED: u32 = 0x00000004;

pub const RESOURCE_ATTRIBUTE_READ_PROTECTED: u32 = 0x00000080;
pub const RESOURCE_ATTRIBUTE_WRITE_PROTECTED: u32 = 0x00000100;
pub const RESOURCE_ATTRIBUTE_EXECUTION_PROTECTED: u32 = 0x00000200;

pub const RESOURCE_ATTRIBUTE_PERSISTENT: u32 = 0x00800000;
pub const RESOURCE_ATTRIBUTE_MORE_RELIABLE: u32 = 0x02000000;

pub const RESOURCE_ATTRIBUTE_SINGLE_BIT_ECC: u32 = 0x00000008;
pub const RESOURCE_ATTRIBUTE_MULTIPLE_BIT_ECC: u32 = 0x00000010;
pub const RESOURCE_ATTRIBUTE_ECC_RESERVED_1: u32 = 0x00000020;
pub const RESOURCE_ATTRIBUTE_ECC_RESERVED_2: u32 = 0x00000040;

pub const RESOURCE_ATTRIBUTE_UNCACHEABLE: u32 = 0x00000400;
pub const RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE: u32 = 0x00000800;
pub const RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE: u32 = 0x00001000;
pub const RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE: u32 = 0x00002000;

pub const RESOURCE_ATTRIBUTE_16_BIT_IO: u32 = 0x00004000;
pub const RESOURCE_ATTRIBUTE_32_BIT_IO: u32 = 0x00008000;
pub const RESOURCE_ATTRIBUTE_64_BIT_IO: u32 = 0x00010000;

pub const RESOURCE_ATTRIBUTE_UNCACHED_EXPORTED: u32 = 0x00020000;
pub const RESOURCE_ATTRIBUTE_READ_ONLY_PROTECTED: u32 = 0x00040000;

pub const RESOURCE_ATTRIBUTE_READ_PROTECTABLE: u32 = 0x00100000;
pub const RESOURCE_ATTRIBUTE_WRITE_PROTECTABLE: u32 = 0x00200000;
pub const RESOURCE_ATTRIBUTE_EXECUTION_PROTECTABLE: u32 = 0x00400000;

pub const RESOURCE_ATTRIBUTE_PERSISTABLE: u32 = 0x01000000;
pub const RESOURCE_ATTRIBUTE_READ_ONLY_PROTECTABLE: u32 = 0x00080000;

#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite)]
pub struct Header {
    pub r#type: u16,
    pub length: u16,
    pub reserved: u32,
}

impl Header {
    pub fn dump(&self) {
        log::info!("Hob:\n");
        log::info!("  header.type            - 0x{:x}\n", self.r#type);
        log::info!("  header.length          - 0x{:x}\n", self.length);
    }
}

pub const HOB_TYPE_HANDOFF: u16 = 0x0001;
pub const HOB_TYPE_MEMORY_ALLOCATION: u16 = 0x0002;
pub const HOB_TYPE_RESOURCE_DESCRIPTOR: u16 = 0x0003;
pub const HOB_TYPE_GUID_EXTENSION: u16 = 0x0004;
pub const HOB_TYPE_FV: u16 = 0x0005;
pub const HOB_TYPE_CPU: u16 = 0x0006;
pub const HOB_TYPE_MEMORY_POOL: u16 = 0x0007;
pub const HOB_TYPE_FV2: u16 = 0x0009;
pub const HOB_TYPE_LOAD_PEIM_UNUSED: u16 = 0x000A;
pub const HOB_TYPE_UEFI_CAPSULE: u16 = 0x000B;
pub const HOB_TYPE_FV3: u16 = 0x000C;
pub const HOB_TYPE_UNUSED: u16 = 0xfffe;
pub const HOB_TYPE_END_OF_HOB_LIST: u16 = 0xffff;

#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite)]
pub struct HandoffInfoTable {
    pub header: Header,
    pub version: u32,
    pub boot_mode: BootMode,
    pub efi_memory_top: PhysicalAddress,
    pub efi_memory_bottom: PhysicalAddress,
    pub efi_free_memory_top: PhysicalAddress,
    pub efi_free_memory_bottom: PhysicalAddress,
    pub efi_end_of_hob_list: PhysicalAddress,
}

impl HandoffInfoTable {
    pub fn dump(&self) {
        log::info!("PhitHob:\n");
        log::info!("  version                - 0x{:x}\n", self.version);
        log::info!("  boot_mode              - 0x{:x}\n", self.boot_mode);
        log::info!(
            "  efi_memory_top         - 0x{:016x}\n",
            self.efi_memory_top
        );
        log::info!(
            "  efi_memory_bottom      - 0x{:016x}\n",
            self.efi_memory_bottom
        );
        log::info!(
            "  efi_free_memory_top    - 0x{:016x}\n",
            self.efi_free_memory_top
        );
        log::info!(
            "  efi_free_memory_bottom - 0x{:016x}\n",
            self.efi_free_memory_bottom
        );
        log::info!(
            "  efi_end_of_hob_list    - 0x{:016x}\n",
            self.efi_end_of_hob_list
        );
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite)]
pub struct MemoryAllocationHeader {
    pub name: [u8; 16], // Guid
    pub memory_base_address: PhysicalAddress,
    pub memory_length: u64,
    pub memory_type: u32, // MemoryType,
    pub reserved: [u8; 4],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite)]
pub struct MemoryAllocation {
    pub header: Header,
    pub alloc_descriptor: MemoryAllocationHeader,
}

impl MemoryAllocation {
    pub fn dump(&self) {
        log::info!(
            "MemoryAllocation 0x{:08x} : 0x{:016x} - 0x{:016x}\n",
            self.alloc_descriptor.memory_type as u32,
            self.alloc_descriptor.memory_base_address,
            self.alloc_descriptor.memory_base_address + self.alloc_descriptor.memory_length - 1,
        );
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite)]
pub struct ResourceDescription {
    pub header: Header,
    pub owner: [u8; 16], // Guid
    pub resource_type: ResourceType,
    pub resource_attribute: ResourceAttributeType,
    pub physical_start: PhysicalAddress,
    pub resource_length: u64,
}

impl ResourceDescription {
    pub fn dump(&self) {
        log::info!(
            "ResourceDescription 0x{:08x} : 0x{:016x} - 0x{:016x} (0x{:08x})\n",
            self.resource_type,
            self.physical_start,
            self.physical_start + self.resource_length - 1,
            self.resource_attribute
        );
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite)]
pub struct FirmwareVolume {
    pub header: Header,
    pub base_address: PhysicalAddress,
    pub length: u64,
}

impl FirmwareVolume {
    pub fn dump(&self) {
        log::info!(
            "FirmwareVolume : 0x{:016x} - 0x{:016x}\n",
            self.base_address,
            self.base_address + self.length - 1
        );
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite)]
pub struct FirmwareVolume2 {
    pub header: Header,
    pub base_address: PhysicalAddress,
    pub length: u64,
    pub fv_name: [u8; 16],   // Guid
    pub file_name: [u8; 16], // Guid
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite)]
pub struct FirmwareVolume3 {
    pub header: Header,
    pub base_address: PhysicalAddress,
    pub length: u64,
    pub authentication_status: u32,
    pub extracted_fv: u8,    // Boolean
    pub fv_name: [u8; 16],   // Guid
    pub file_name: [u8; 16], // Guid
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Pread, Pwrite)]
pub struct Cpu {
    pub header: Header,
    pub size_of_memory_space: u8,
    pub size_of_io_space: u8,
    pub reserved: [u8; 6],
}

impl Cpu {
    pub fn dump(&self) {
        log::info!(
            "Cpu : mem size {} , io size {}\n",
            self.size_of_memory_space,
            self.size_of_io_space
        );
    }
}

#[derive(Copy, Clone, Debug, Pread, Pwrite)]
pub struct GuidExtension {
    pub header: Header,
    pub name: [u8; 16], // Guid
}
