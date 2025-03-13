// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

extern crate alloc;

use alloc::vec::Vec;
use core::arch::asm;
use core::cmp::min;
use core::ops::RangeInclusive;
use td_exception::idt::DescriptorTablePointer;
use td_layout::memslice::{get_mem_slice_mut, SliceType};
use tdx_tdcall::{self, tdx::*};

use crate::asm::{ap_relocated_func_addr, ap_relocated_func_size};

// The count of AP to wakeup is limited by the heap size that can be used for stack allocation
// The maximum size of memory used for AP stacks is 30 KB.
const MAX_WORKING_AP_COUNT: u32 = 15;
const AP_TEMP_STACK_SIZE: usize = 0x800;
const AP_TEMP_STACK_TOTAL_SIZE: usize = MAX_WORKING_AP_COUNT as usize * AP_TEMP_STACK_SIZE;
static AP_TEMP_STACK: [u8; AP_TEMP_STACK_TOTAL_SIZE] = [0; AP_TEMP_STACK_TOTAL_SIZE];

const ACCEPT_CHUNK_SIZE: u64 = 0x2000000;
const ACCEPT_PAGE_SIZE: u64 = 0x200000;
const MAILBOX_SIZE: usize = 0x1000;

#[derive(Debug)]
pub enum MailboxError {
    Relocation,
}

mod spec {
    pub type Field = ::core::ops::Range<usize>;

    pub const COMMAND: Field = 0..4;
    pub const APIC_ID: Field = 4..8;
    pub const WAKEUP_VECTOR: Field = 0x08..0x10;
    pub const FW_ARGS: usize = 0x800;
    pub const CPU_ARRIVAL: Field = 0x900..0x904;
    pub const CPU_EXITING: Field = 0xa00..0xa04;

    pub const MP_WAKEUP_COMMAND_NOOP: u32 = 0;
    pub const MP_WAKEUP_COMMAND_WAKEUP: u32 = 1;
    pub const MP_WAKEUP_COMMAND_SLEEP: u32 = 2;
    pub const MP_WAKEUP_COMMAND_ACCEPT_PAGES: u32 = 3;
    pub const MP_WAKEUP_COMMAND_AVAILABLE: u32 = 4;
    pub const MP_WAKEUP_COMMAND_SET_PAGING: u32 = 5;
    pub const MP_WAKEUP_COMMAND_SET_IDT: u32 = 6;

    pub const MAILBOX_APICID_INVALID: u32 = 0xffffffff;
    pub const MAILBOX_APICID_BROADCAST: u32 = 0xfffffffe;
}

struct MailBox<'a> {
    buffer: &'a mut [u8],
}

impl MailBox<'_> {
    fn read_volatile<T>(src: *const T) -> T {
        // Safety: mailbox memory is always valid
        // Mailbox memory should be read/written using volatile, it may be changed by AP.
        unsafe { core::ptr::read_volatile(src) }
    }

    fn write_volatile<T>(dst: *mut T, src: T) {
        // Safety: mailbox memory is always valid
        unsafe { core::ptr::write_volatile(dst, src) }
    }

    fn new(buffer: &mut [u8]) -> MailBox {
        MailBox { buffer }
    }

    fn apic_id(&self) -> u32 {
        let p_apic_id = self.buffer[spec::APIC_ID].as_ptr() as *const u32;
        MailBox::read_volatile(p_apic_id)
    }

    fn fw_arg(&self, index: usize) -> u64 {
        let offset = spec::FW_ARGS + index * 8;
        let p_fw_arg = self.buffer[offset..offset + 8].as_ptr() as *const u64;
        MailBox::read_volatile(p_fw_arg)
    }

    fn cpu_arrival(&self) -> u32 {
        let p_cpu_arrival = self.buffer[spec::CPU_ARRIVAL].as_ptr() as *const u32;
        MailBox::read_volatile(p_cpu_arrival)
    }

    fn cpu_exiting(&self) -> u32 {
        let p_cpu_exiting = self.buffer[spec::CPU_EXITING].as_ptr() as *const u32;
        MailBox::read_volatile(p_cpu_exiting)
    }

    fn set_command(&mut self, command: u32) {
        let p_command = self.buffer[spec::COMMAND].as_ptr() as *mut u32;
        MailBox::write_volatile(p_command, command);
    }

    fn set_apic_id(&mut self, apic_id: u32) {
        let p_apic_id = self.buffer[spec::APIC_ID].as_ptr() as *mut u32;
        MailBox::write_volatile(p_apic_id, apic_id);
    }

    fn set_wakeup_vector(&mut self, wakeup_vector: u32) {
        let p_wakeup_vector = self.buffer[spec::WAKEUP_VECTOR].as_ptr() as *mut u32;
        MailBox::write_volatile(p_wakeup_vector, wakeup_vector);
    }

    fn set_fw_arg(&mut self, index: usize, fw_arg: u64) {
        let offset = spec::FW_ARGS + index * 8;
        let p_fw_arg = self.buffer[offset..offset + 8].as_ptr() as *mut u64;
        MailBox::write_volatile(p_fw_arg, fw_arg);
    }
}

fn cpu_pause() {
    unsafe { asm!("pause") };
}

fn make_apic_range(end: u32) -> RangeInclusive<u32> {
    // 0 is the bootstrap processor running this code
    let start = 1;

    RangeInclusive::new(start, end)
}

// Wait for AP to response the command set by BSP if needed.
// Typically AP will set the APIC ID field in mailbox to be invalid
fn wait_for_ap_response(mail_box: &mut MailBox) {
    loop {
        if mail_box.apic_id() == spec::MAILBOX_APICID_INVALID {
            x86::fence::mfence();
            mail_box.set_command(spec::MP_WAKEUP_COMMAND_NOOP);
            break;
        } else {
            cpu_pause();
        }
    }
}

// Wait for APs to arrive by checking if they are available
fn wait_for_ap_arrive(ap_num: u32) {
    // Safety:
    // BSP is the owner of the mailbox area, and APs cooperate with BSP to access the mailbox area.
    let mut mail_box = unsafe { MailBox::new(get_mem_slice_mut(SliceType::MailBox)) };
    for i in make_apic_range(ap_num) {
        mail_box.set_command(spec::MP_WAKEUP_COMMAND_AVAILABLE);
        x86::fence::mfence();
        mail_box.set_apic_id(i);
        wait_for_ap_response(&mut mail_box);
    }
}

pub fn ap_assign_work(cpu_index: u32, stack_top: u64, entry: u32) {
    // Safety:
    // BSP is the owner of the mailbox area, and APs cooperate with BSP to access the mailbox area.
    let mut mail_box = unsafe { MailBox::new(get_mem_slice_mut(SliceType::MailBox)) };

    mail_box.set_wakeup_vector(entry);
    mail_box.set_fw_arg(0, stack_top);
    mail_box.set_command(spec::MP_WAKEUP_COMMAND_ACCEPT_PAGES);
    x86::fence::mfence();
    mail_box.set_apic_id(cpu_index);

    wait_for_ap_response(&mut mail_box);
}

extern "win64" fn parallel_accept_memory(cpu_index: u64) {
    // Safety:
    // During this state, all the BSPs/APs are accessing the mailbox in shared immutable mode.
    let mail_box = unsafe { MailBox::new(get_mem_slice_mut(SliceType::MailBox)) };

    // The cpu number, start and end address of memory to be accepted is
    // set to mailbox fw arguments by mp_accept_memory_resource_range()
    let cpu_num = mail_box.fw_arg(1);
    let start = mail_box.fw_arg(2);
    let end = mail_box.fw_arg(3);

    let stride = ACCEPT_CHUNK_SIZE * cpu_num;
    let mut phys_addr = start + ACCEPT_CHUNK_SIZE * cpu_index;

    while phys_addr < end {
        let page_num = min(ACCEPT_CHUNK_SIZE, end - phys_addr) / ACCEPT_PAGE_SIZE;
        #[cfg(not(feature = "no-tdaccept"))]
        td_accept_pages(phys_addr, page_num, ACCEPT_PAGE_SIZE);
        phys_addr += stride;
    }
}

pub fn accept_memory_resource_range(mut cpu_num: u32, address: u64, size: u64) {
    log::info!(
        "mp_accept_memory_resource_range: 0x{:x} - 0x{:x} ... (wait for seconds)\n",
        address,
        size
    );

    let active_ap_cnt = if cpu_num - 1 > MAX_WORKING_AP_COUNT {
        MAX_WORKING_AP_COUNT
    } else {
        cpu_num - 1
    };

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

    wait_for_ap_arrive(active_ap_cnt);

    // Safety:
    // BSP is the owner of the mailbox area, and APs cooperate with BSP to access the mailbox area.
    let mut mail_box = unsafe { MailBox::new(get_mem_slice_mut(SliceType::MailBox)) };

    // BSP calles the same function parallel_accept_memory to accept memory,
    // so set the firmware arguments here.
    // To do: Set these parameter only in ap_assign_work() when there's
    // multiple cpus.
    mail_box.set_fw_arg(1, active_ap_cnt as u64 + 1);
    mail_box.set_fw_arg(2, address + align_low);
    mail_box.set_fw_arg(3, address + size);

    if major_part > 0 {
        // 0 is the bootstrap processor running this code
        for i in make_apic_range(active_ap_cnt) {
            // rsp should be at the top of the memory allocated for each ap
            let stack_top = AP_TEMP_STACK.as_ptr() as u64 + i as u64 * AP_TEMP_STACK_SIZE as u64;
            ap_assign_work(i, stack_top, parallel_accept_memory as *const () as u32);
        }
    }

    parallel_accept_memory(0);

    #[cfg(not(feature = "no-tdaccept"))]
    td_accept_pages(address, align_low / PAGE_SIZE_4K, PAGE_SIZE_4K);
    #[cfg(not(feature = "no-tdaccept"))]
    td_accept_pages(
        address + align_low + major_part,
        align_high / PAGE_SIZE_4K,
        PAGE_SIZE_4K,
    );

    wait_for_ap_arrive(active_ap_cnt);
    log::info!("mp_accept_memory_resource_range: done\n");
}

pub fn relocate_mailbox(new_mailbox: &mut [u8]) -> Result<(), MailboxError> {
    // Safety:
    // During this state, all the BSPs/APs are accessing the mailbox in shared immutable mode.
    let mut mail_box = unsafe { MailBox::new(get_mem_slice_mut(SliceType::MailBox)) };

    // Get the new AP function and its size
    let func_addr = ap_relocated_func_addr();
    let func_size = ap_relocated_func_size();

    // Ensure that the Mailbox memory can hold the AP loop function
    if func_size as usize > new_mailbox.len() {
        return Err(MailboxError::Relocation);
    }

    // Safety:
    // the code size is calculated according to the ASM symbol address
    // in the code section
    let ap_func =
        unsafe { core::slice::from_raw_parts(func_addr as *const u8, func_size as usize) };

    // Copy AP function into Mailbox memory
    // The layout of Mailbox memory: |---Mailbox---|---Relocated function---|
    new_mailbox[MAILBOX_SIZE..MAILBOX_SIZE + ap_func.len()].copy_from_slice(ap_func);

    let new_mailbox_address = new_mailbox.as_ptr() as u64;
    if new_mailbox_address + MAILBOX_SIZE as u64 > u32::MAX as u64 {
        return Err(MailboxError::Relocation);
    }

    // Wakeup APs to complete the relocation of mailbox and AP function
    mail_box.set_wakeup_vector(new_mailbox_address as u32 + MAILBOX_SIZE as u32);
    // Put new mailbox base address to the first FW arg
    mail_box.set_fw_arg(0, new_mailbox_address);

    // Broadcast the wakeup command to all the APs
    mail_box.set_command(spec::MP_WAKEUP_COMMAND_WAKEUP);
    mail_box.set_apic_id(spec::MAILBOX_APICID_BROADCAST);

    Ok(())
}

fn ap_set_cr3(cpu_index: u32, cr3: u64) {
    // Safety:
    // During this state, all the BSPs/APs are accessing the mailbox in shared immutable mode.
    let mut mail_box = unsafe { MailBox::new(get_mem_slice_mut(SliceType::MailBox)) };

    // Put new page table base address to the first FW arg
    mail_box.set_fw_arg(0, cr3 as u64);

    // Set the set-paging command and wakeup the target AP.
    mail_box.set_command(spec::MP_WAKEUP_COMMAND_SET_PAGING);
    mail_box.set_apic_id(cpu_index);

    wait_for_ap_response(&mut mail_box);
}

fn ap_set_idt(cpu_index: u32, idt_ptr: &DescriptorTablePointer) {
    // Safety:
    // During this state, all the BSPs/APs are accessing the mailbox in shared immutable mode.
    let mut mail_box = unsafe { MailBox::new(get_mem_slice_mut(SliceType::MailBox)) };

    // Put the IDT base address to the first FW arg
    mail_box.set_fw_arg(0, idt_ptr as *const _ as u64);

    // Set the set-paging command and wakeup the target AP.
    mail_box.set_command(spec::MP_WAKEUP_COMMAND_SET_IDT);
    mail_box.set_apic_id(cpu_index);

    wait_for_ap_response(&mut mail_box);
}

pub fn relocate_page_table(cpu_num: u32, page_table_base: u64) {
    for cpu_index in make_apic_range(cpu_num - 1) {
        ap_set_cr3(cpu_index, page_table_base);
    }
}

pub fn set_idt(cpu_num: u32, idt_ptr: &DescriptorTablePointer) {
    for cpu_index in make_apic_range(cpu_num - 1) {
        ap_set_idt(cpu_index, idt_ptr);
    }
}
