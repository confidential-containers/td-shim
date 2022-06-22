# Copyright (c) 2022 Intel Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent

.set TDVMCALL_EXPOSE_REGS_MASK,           0xffec
.set TDVMCALL,                            0x0
.set INSTRUCTION_CPUID,                   0xa

.set CommandOffset,                       0
.set ApicIdOffset,                        0x4
.set WakeupVectorOffset,                  0x8

.set MpProtectedModeWakeupCommandNoop,    0
.set MpProtectedModeWakeupCommandWakeup,  1
.set MpProtectedModeWakeupCommandSleep,   2

.set MailboxApicIdInvalid,                0xffffffff
.set MailboxApicIdBroadcast,              0xfffffffe

.section .text
#---------------------------------------------------------------------
#  ap_relocated_func_size (
#       size: *mut u64, // rcx
#  );
#---------------------------------------------------------------------
.global ap_relocated_func_size
ap_relocated_func_size:
    push       rax
    push       rbx
    lea        rax, .ap_relocated_func_end
    lea        rbx, ap_relocated_func
    sub        rax, rbx
    mov        qword ptr[rcx], rax
    pop        rbx
    pop        rax
    ret

#--------------------------------------------------------------------
# ap_relocated_vector
#
# rbx:  Relocated mailbox address
# rbp:  vCpuId
#--------------------------------------------------------------------
.global ap_relocated_func
ap_relocated_func:
    #
    # Get the APIC ID via TDVMCALL
    mov         rax, TDVMCALL
    mov         rcx, TDVMCALL_EXPOSE_REGS_MASK
    mov         r10, 0
    mov         r11, INSTRUCTION_CPUID
    mov         r12, 0xb
    mov         r13, 0
    # TDVMCALL
    .byte       0x66, 0x0f, 0x01, 0xcc
    test        rax, rax
    jnz         .panic
    #
    # r8 will hold the APIC ID of current AP
    mov         r8, r15

.check_apicid:
    #
    # Determine if this is a broadcast or directly for my apic-id, if not, ignore
    cmp     dword ptr[rbx + ApicIdOffset], MailboxApicIdBroadcast
    je      .check_command
    cmp     dword ptr[rbx + ApicIdOffset], r8d
    jne     .check_apicid

.check_command:
    mov     eax, dword ptr[rbx + CommandOffset]
    cmp     eax, MpProtectedModeWakeupCommandNoop
    je      .check_apicid

    cmp     eax, MpProtectedModeWakeupCommandWakeup
    je      .wakeup

    jmp     .check_apicid

.wakeup:
    #
    # BSP sets these variables before unblocking APs
    mov     rax, 0
    mov     eax, dword ptr[rbx + WakeupVectorOffset]

    #
    # Clear the command as the acknowledgement that the wake up command is received
    mov     qword ptr[rbx + CommandOffset], MpProtectedModeWakeupCommandNoop
    nop
    jmp     rax

.panic:
    ud2

.ap_relocated_func_end:
