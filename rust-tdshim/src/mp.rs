// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::{
    acpi::{self, GenericSdtHeader},
    memslice::{get_mem_slice_mut, SliceType},
};
use core::convert::TryInto;
use core::mem::size_of;
use core::{cmp::min, slice};
use tdx_tdcall::tdx;
use zerocopy::{AsBytes, FromBytes};

extern crate alloc;
use alloc::vec::Vec;

const ACCEPT_CHUNK_SIZE: u64 = 0x2000000;
const ACCEPT_PAGE_SIZE: u64 = 0x200000;
const PAGE_SIZE_2M: u64 = 0x200000;
const PAGE_SIZE_4K: u64 = 0x1000;

const MP_WAKEUP_COMMAND_NOOP: u32 = 0;
const MP_WAKEUP_COMMAND_WAKEUP: u32 = 1;
const MP_WAKEUP_COMMAND_SLEEP: u32 = 2;
const MP_WAKEUP_COMMAND_ACCEPT_PAGES: u32 = 3;

const MAILBOX_APICID_INVALID: u32 = 0xffffffff;
const MAILBOX_APICID_BROADCAST: u32 = 0xfffffffe;

const MADT_MAX_SIZE: usize = 0x400;

const NUM_8259_IRQS: usize = 16;

const ACPI_1_0_PROCESSOR_LOCAL_APIC: u8 = 0x00;
const ACPI_1_0_IO_APIC: u8 = 0x01;
const ACPI_1_0_INTERRUPT_SOURCE_OVERRIDE: u8 = 0x02;
const ACPI_MADT_MPWK_STRUCT_TYPE: u8 = 0x10;
const ACPI_1_0_LOCAL_APIC_NMI: u8 = 0x04;

pub mod mailbox {
    pub type Field = ::core::ops::Range<usize>;

    pub const COMMAND: Field = 0..4;
    pub const APIC_ID: Field = 4..8;
    pub const WAKEUP_VECTOR: Field = 0x08..0x10;
    pub const CPU_ARRIVAL: Field = 0x900..0x904;
    pub const CPU_EXITING: Field = 0xa00..0xa04;

    pub const FW_ARGS: usize = 0x800;
}

pub struct MailBox<'a> {
    buffer: &'a mut [u8],
}

impl MailBox<'_> {
    fn read_volatile<T>(src: *const T) -> T {
        // Safety: mailbox memory is always valid
        // Mailbox memory should be read/written using volatile,
        // it may be changed by AP.
        unsafe { core::ptr::read_volatile(src) }
    }

    fn write_volatile<T>(dst: *mut T, src: T) {
        unsafe { core::ptr::write_volatile(dst, src) }
    }

    pub fn new(buffer: &mut [u8]) -> MailBox {
        MailBox { buffer }
    }

    pub fn apic_id(&self) -> u32 {
        let p_apic_id = self.buffer[mailbox::APIC_ID].as_ptr() as *const u32;
        MailBox::read_volatile(p_apic_id)
    }

    pub fn fw_arg(&self, index: usize) -> u64 {
        let offset = mailbox::FW_ARGS + index * 8;
        let p_fw_arg = self.buffer[offset..offset + 8].as_ptr() as *const u64;
        MailBox::read_volatile(p_fw_arg)
    }

    pub fn cpu_arrival(&self) -> u32 {
        let p_cpu_arrival = self.buffer[mailbox::CPU_ARRIVAL].as_ptr() as *const u32;
        MailBox::read_volatile(p_cpu_arrival)
    }

    pub fn cpu_exiting(&self) -> u32 {
        let p_cpu_exiting = self.buffer[mailbox::CPU_EXITING].as_ptr() as *const u32;
        MailBox::read_volatile(p_cpu_exiting)
    }

    pub fn set_command(&mut self, command: u32) {
        let p_command = self.buffer[mailbox::COMMAND].as_ptr() as *mut u32;
        MailBox::write_volatile(p_command, command);
    }

    pub fn set_apic_id(&mut self, apic_id: u32) {
        let p_apic_id = self.buffer[mailbox::APIC_ID].as_ptr() as *mut u32;
        MailBox::write_volatile(p_apic_id, apic_id);
    }

    pub fn set_wakeup_vector(&mut self, wakeup_vector: u32) {
        let p_wakeup_vector = self.buffer[mailbox::WAKEUP_VECTOR].as_ptr() as *mut u32;
        MailBox::write_volatile(p_wakeup_vector, wakeup_vector);
    }

    pub fn set_fw_arg(&mut self, index: usize, fw_arg: u64) {
        let offset = mailbox::FW_ARGS + index * 8;
        let p_fw_arg = self.buffer[offset..offset + 8].as_ptr() as *mut u64;
        MailBox::write_volatile(p_fw_arg, fw_arg);
    }

    pub fn set_cpu_exiting(&mut self, exiting: u32) {
        let p_cpu_exiting = self.buffer[mailbox::CPU_EXITING].as_ptr() as *mut u32;
        MailBox::write_volatile(p_cpu_exiting, exiting);
    }
}

fn td_accept_pages(address: u64, pages: u64, page_size: u64) {
    for i in 0..pages {
        let mut accept_addr = address + i * page_size;
        let accept_level = if page_size == PAGE_SIZE_2M { 1 } else { 0 };
        let res = tdx::tdcall_accept_page(accept_addr | accept_level).map_err(|e| {
            if e == tdx::TdCallError::TdxExitReasonPageSizeMismatch {
                if page_size == PAGE_SIZE_4K {
                    log::error!(
                        "Accept Page Error: 0x{:x}, page_size: {}\n",
                        accept_addr,
                        page_size
                    );
                } else {
                    td_accept_pages(accept_addr, 512, PAGE_SIZE_4K);
                }
            }
        });
    }
}

fn parallel_accept_memory(apic_id: u64) {
    let mail_box = MailBox::new(get_mem_slice_mut(SliceType::MailBox));

    // The cpu number, start and end address of memory to be accepted is
    // set to mailbox fw arguments by mp_accept_memory_resource_range()
    let cpu_num = mail_box.fw_arg(1);
    let start = mail_box.fw_arg(2);
    let end = mail_box.fw_arg(3);

    let stride = ACCEPT_CHUNK_SIZE * cpu_num;
    let mut phys_addr = start + ACCEPT_CHUNK_SIZE * apic_id;

    while phys_addr < end {
        let page_num = min(ACCEPT_CHUNK_SIZE, end - phys_addr) / ACCEPT_PAGE_SIZE;
        td_accept_pages(phys_addr, page_num, ACCEPT_PAGE_SIZE);
        phys_addr += stride;
    }
}

fn wait_for_ap_arrive(cpu_num: u32) {
    let mut mail_box = MailBox::new(get_mem_slice_mut(SliceType::MailBox));
    log::info!("Waiting for APs to arrive...\n");
    loop {
        if mail_box.cpu_arrival() == cpu_num - 1 {
            log::info!("All APs has arrived\n");
            break;
        }
    }
    mail_box.set_cpu_exiting(cpu_num - 1);
}

fn wait_for_ap_exit(cpu_num: u32) {
    let mail_box = MailBox::new(get_mem_slice_mut(SliceType::MailBox));
    log::info!("Waiting for APs to exit...\n");
    loop {
        let cpu_exit = mail_box.cpu_exiting();

        if cpu_exit == 0 {
            log::info!("All APs has exited\n");
            break;
        }
    }
}

pub fn ap_assign_work(apic_id: u32, stack: u64, entry: u32) {
    let mut mail_box = MailBox::new(get_mem_slice_mut(SliceType::MailBox));
    mail_box.set_wakeup_vector(entry);
    mail_box.set_fw_arg(0, stack);

    mail_box.set_apic_id(apic_id);
    mail_box.set_command(MP_WAKEUP_COMMAND_ACCEPT_PAGES);

    loop {
        let wakeup_apic_id = mail_box.apic_id();
        if wakeup_apic_id == MAILBOX_APICID_INVALID {
            mail_box.set_command(MP_WAKEUP_COMMAND_NOOP);
            log::info!("Successfully wakeup AP #{}\n", apic_id);
            break;
        }
    }
}

pub fn mp_accept_memory_resource_range(cpu_num: u32, address: u64, size: u64) {
    log::info!(
        "mp_accept_memory_resource_range: 0x{:x} - 0x{:x} ... (wait for seconds)\n",
        address,
        size
    );

    let mut align_low = if address & (ACCEPT_PAGE_SIZE - 1) == 0 {
        0
    } else {
        min(size, ACCEPT_PAGE_SIZE - (address & (ACCEPT_PAGE_SIZE - 1)))
    };
    let mut major_part = size - align_low;
    let mut align_high = 0u64;

    if size > ACCEPT_PAGE_SIZE {
        major_part = (size - align_low) & !(ACCEPT_PAGE_SIZE - 1);
        if major_part < ACCEPT_PAGE_SIZE {
            align_low += major_part;
            major_part = 0;
        } else {
            align_high = size - align_low - major_part;
        }
    }

    wait_for_ap_arrive(cpu_num);

    let mut stacks: Vec<u8> = Vec::with_capacity(0x1000 * (cpu_num as usize));
    let mut mail_box = MailBox::new(get_mem_slice_mut(SliceType::MailBox));

    // BSP calles the same function parallel_accept_memory to accept memory,
    // so set the firmware arguments here.
    // To do: Set these parameter only in ap_assign_work() when there's
    // multiple cpus.
    mail_box.set_fw_arg(1, cpu_num as u64);
    mail_box.set_fw_arg(2, address + align_low);
    mail_box.set_fw_arg(3, address + size);

    if major_part > 0 {
        for i in 1..cpu_num {
            let ap_stack = stacks.as_ptr() as u64 + i as u64 * 0x800;

            ap_assign_work(i, ap_stack, parallel_accept_memory as *const () as u32);
        }
    }

    parallel_accept_memory(0);

    td_accept_pages(address, align_low / PAGE_SIZE_4K, PAGE_SIZE_4K);

    td_accept_pages(
        address + align_low + major_part,
        align_high / PAGE_SIZE_4K,
        PAGE_SIZE_4K,
    );

    wait_for_ap_exit(cpu_num);
    log::info!("mp_accept_memory_resource_range: done\n");
}

pub struct Madt {
    pub data: [u8; MADT_MAX_SIZE],
    pub size: usize,
}

impl Madt {
    fn default() -> Self {
        Madt {
            data: [0; MADT_MAX_SIZE],
            size: 0,
        }
    }

    fn write(&mut self, data: &[u8]) {
        self.data[self.size..self.size + data.len()].copy_from_slice(data);
        self.size += data.len();
    }

    fn update_checksum(&mut self) {
        let checksum = acpi::calculate_checksum(&self.data[0..self.size]);
        self.data[9] = checksum;
    }
}

#[repr(packed)]
#[derive(Default, AsBytes, FromBytes)]
struct LocalApic {
    pub r#type: u8,
    pub length: u8,
    pub processor_id: u8,
    pub apic_id: u8,
    pub flags: u32,
}

#[repr(packed)]
#[derive(Default, AsBytes, FromBytes)]
struct LocalApicNmi {
    pub r#type: u8,
    pub length: u8,
    pub acpi_processor_id: u8,
    pub flags: u16,
    pub local_apic_inti: u8,
}

#[repr(packed)]
#[derive(Default, AsBytes, FromBytes)]
struct IoApic {
    pub r#type: u8,
    pub length: u8,
    pub ioapic_id: u8,
    _reserved: u8,
    pub apic_address: u32,
    pub gsi_base: u32,
}

#[repr(packed)]
#[derive(Default, AsBytes, FromBytes)]
struct InterruptSourceOverride {
    pub r#type: u8,
    pub length: u8,
    pub bus: u8,
    pub source: u8,
    pub gsi: u32,
    pub flags: u16,
}

#[repr(packed)]
#[derive(Default, AsBytes, FromBytes)]
struct MadtMpwkStruct {
    r#type: u8,
    length: u8,
    mail_box_version: u16,
    reserved: u32,
    mail_box_address: u64,
}

pub fn create_madt(cpu_num: u8, mailbox_base: u64) -> Madt {
    log::info!("create_madt(): cpu_num: {:x}\n", cpu_num);

    let table_length = size_of::<GenericSdtHeader>()
        + 8
        + cpu_num as usize * size_of::<LocalApic>()
        + size_of::<IoApic>()
        + NUM_8259_IRQS * size_of::<InterruptSourceOverride>()
        + size_of::<LocalApicNmi>()
        + size_of::<MadtMpwkStruct>();

    let mut madt = Madt::default();

    let header = GenericSdtHeader::new(*b"APIC", table_length as u32, 1);

    madt.write(header.as_bytes());

    madt.write(&0xfee00000u32.to_le_bytes());
    madt.write(&1u32.to_le_bytes());

    for cpu in 0..cpu_num {
        let lapic = LocalApic {
            r#type: ACPI_1_0_PROCESSOR_LOCAL_APIC,
            length: size_of::<LocalApic>() as u8,
            processor_id: cpu as u8,
            apic_id: cpu as u8,
            flags: 1,
        };
        madt.write(lapic.as_bytes());
    }

    let ioapic = IoApic {
        r#type: ACPI_1_0_IO_APIC,
        length: size_of::<IoApic>() as u8,
        ioapic_id: cpu_num,
        apic_address: 0xFEC00000,
        gsi_base: 0,
        ..Default::default()
    };
    madt.write(ioapic.as_bytes());

    let iso = InterruptSourceOverride {
        r#type: ACPI_1_0_INTERRUPT_SOURCE_OVERRIDE,
        length: size_of::<InterruptSourceOverride>() as u8,
        bus: 0,
        source: 0,
        gsi: 2,
        flags: 5,
    };
    madt.write(iso.as_bytes());

    for irq in 1..NUM_8259_IRQS {
        let iso = InterruptSourceOverride {
            r#type: ACPI_1_0_INTERRUPT_SOURCE_OVERRIDE,
            length: size_of::<InterruptSourceOverride>() as u8,
            bus: 0,
            source: irq as u8,
            gsi: irq as u32,
            flags: 5,
        };
        madt.write(iso.as_bytes());
    }

    let nmi = LocalApicNmi {
        r#type: ACPI_1_0_LOCAL_APIC_NMI,
        length: size_of::<LocalApicNmi>() as u8,
        acpi_processor_id: 0xff,
        flags: 0,
        local_apic_inti: 0x01,
    };
    madt.write(nmi.as_bytes());

    let mpwk = MadtMpwkStruct {
        r#type: ACPI_MADT_MPWK_STRUCT_TYPE,
        length: size_of::<MadtMpwkStruct>() as u8,
        mail_box_version: 1,
        reserved: 0,
        mail_box_address: mailbox_base,
    };
    madt.write(mpwk.as_bytes());

    madt.update_checksum();
    madt
}
