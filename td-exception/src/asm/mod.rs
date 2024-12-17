use core::arch::global_asm;

global_asm!(include_str!("handler.asm"));

extern "C" {
    pub(crate) static interrupt_handler_table: u8;
}
