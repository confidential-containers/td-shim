use crate::e820::E820Table;
use crate::ipl;
use crate::memory;
use crate::memslice::{self, *};
use crate::{acpi::AcpiTables, memory::Memory};
use alloc::vec::Vec;
use core::mem::size_of;
use r_efi::efi;
use scroll::Pwrite;
use td_layout::build_time::*;
use td_layout::runtime::*;
use td_shim::e820::E820Type;
use td_shim::{TD_ACPI_TABLE_HOB_GUID, TD_E820_TABLE_HOB_GUID};
use td_shim_interface::td_uefi_pi::pi::hob::ResourceDescription;
use td_shim_interface::td_uefi_pi::{hob, pi, pi::guid};

#[derive(Debug)]
pub enum PayloadHobError {
    OutOfResource,
}

pub struct PayloadHob {
    memory: &'static mut [u8],
    end: usize,
}

impl PayloadHob {
    pub fn new(memory: &'static mut [u8]) -> Option<Self> {
        if memory.len() < size_of::<pi::hob::HandoffInfoTable>() {
            return None;
        }

        Some(PayloadHob {
            memory,
            // Left a margin to hold handoff info table
            end: size_of::<pi::hob::HandoffInfoTable>(),
        })
    }

    fn append(&mut self, buf: &[u8]) -> Result<(), PayloadHobError> {
        if self.end + buf.len() > self.memory.len() {
            return Err(PayloadHobError::OutOfResource);
        }

        self.memory[self.end..self.end + buf.len()].copy_from_slice(buf);
        self.end += buf.len();

        Ok(())
    }

    pub fn finish(&mut self, memory_top: u64, memory_bottom: u64) -> Result<(), PayloadHobError> {
        let end_off_hob = pi::hob::Header {
            r#type: pi::hob::HOB_TYPE_END_OF_HOB_LIST,
            length: size_of::<pi::hob::Header>() as u16,
            reserved: 0,
        };
        self.append(end_off_hob.as_bytes())?;

        let handoff_info_table = pi::hob::HandoffInfoTable {
            header: pi::hob::Header {
                r#type: pi::hob::HOB_TYPE_HANDOFF,
                length: core::mem::size_of::<pi::hob::HandoffInfoTable>() as u16,
                reserved: 0,
            },
            version: 9u32,
            boot_mode: pi::boot_mode::BOOT_WITH_FULL_CONFIGURATION,
            efi_memory_top: memory_top,
            efi_memory_bottom: memory_bottom,
            efi_free_memory_top: memory_top,
            efi_free_memory_bottom: memory_bottom,
            efi_end_of_hob_list: self.memory.as_ptr() as u64 + self.end as u64,
        };
        // The region for HandoffInfoTable is reserved in payload memory.
        self.memory[0..0 + size_of::<pi::hob::HandoffInfoTable>()]
            .copy_from_slice(handoff_info_table.as_bytes());

        Ok(())
    }

    pub fn add_resource(&mut self, resource: &ResourceDescription) -> Result<(), PayloadHobError> {
        self.append(resource.as_bytes())?;
        Ok(())
    }

    pub fn add_mem_allocation(
        &mut self,
        name: &guid::Guid,
        start: u64,
        length: u64,
        alloc_type: u32,
    ) -> Result<(), PayloadHobError> {
        let hob = pi::hob::MemoryAllocation {
            header: pi::hob::Header {
                r#type: pi::hob::HOB_TYPE_MEMORY_ALLOCATION,
                length: size_of::<pi::hob::MemoryAllocation>() as u16,
                reserved: 0,
            },
            alloc_descriptor: pi::hob::MemoryAllocationHeader {
                name: *name.as_bytes(),
                memory_base_address: start,
                memory_length: length,
                memory_type: alloc_type,
                reserved: [0u8; 4],
            },
        };

        self.append(hob.as_bytes())?;
        Ok(())
    }

    pub fn add_guided_data(
        &mut self,
        name: &guid::Guid,
        data: &[u8],
    ) -> Result<(), PayloadHobError> {
        // Length of GUIDed data must align with 8 bytes
        let data_len = (data.len() + 7) / 8 * 8;

        let hob = pi::hob::GuidExtension {
            header: pi::hob::Header {
                r#type: pi::hob::HOB_TYPE_GUID_EXTENSION,
                length: (data_len + size_of::<pi::hob::GuidExtension>()) as u16,
                reserved: 0,
            },
            name: *name.as_bytes(),
        };
        self.append(hob.as_bytes())?;

        if data_len + self.end > self.memory.len() {
            return Err(PayloadHobError::OutOfResource);
        }
        self.memory[self.end..self.end + data.len()].copy_from_slice(data);
        self.end += data_len;
        Ok(())
    }

    pub fn add_cpu(&mut self, memory_space: u8, io_space: u8) -> Result<(), PayloadHobError> {
        let hob = pi::hob::Cpu {
            header: pi::hob::Header {
                r#type: pi::hob::HOB_TYPE_CPU,
                length: size_of::<pi::hob::Cpu>() as u16,
                reserved: 0,
            },
            size_of_memory_space: memory_space,
            size_of_io_space: io_space,
            reserved: [0u8; 6],
        };
        self.append(hob.as_bytes())?;
        Ok(())
    }

    pub fn add_fv(&mut self, start: u64, length: u64) -> Result<(), PayloadHobError> {
        let hob = pi::hob::FirmwareVolume {
            header: pi::hob::Header {
                r#type: pi::hob::HOB_TYPE_FV,
                length: size_of::<pi::hob::FirmwareVolume>() as u16,
                reserved: 0,
            },
            base_address: start,
            length,
        };
        self.append(hob.as_bytes())?;
        Ok(())
    }
}

pub fn build_payload_hob(acpi_tables: &Vec<&[u8]>, memory: &Memory) -> Option<PayloadHob> {
    // Reuse the ACPI memory to build the payload HOB.
    let mut payload_hob =
        PayloadHob::new(memory.get_dynamic_mem_slice_mut(memslice::SliceType::Acpi))?;

    payload_hob.add_cpu(memory::cpu_get_memory_space_size(), 16);

    for &table in acpi_tables {
        payload_hob
            .add_guided_data(&TD_ACPI_TABLE_HOB_GUID, table)
            .ok()?;
    }

    let mut e820 = memory.create_e820();

    log::info!("e820 table: {:x?}\n", e820.as_slice());
    payload_hob
        .add_guided_data(&TD_E820_TABLE_HOB_GUID, e820.as_bytes())
        .ok()?;

    let memory_top = e820
        .as_slice()
        .iter()
        .map(|entry| entry.addr + entry.size)
        .max()?;
    let memory_bottom = e820.as_slice().iter().map(|entry| entry.addr).min()?;
    payload_hob.finish(memory_top, memory_bottom).ok()?;

    Some(payload_hob)
}
