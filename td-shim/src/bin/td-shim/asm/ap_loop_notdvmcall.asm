# Copyright (c) 2022, 2025 Intel Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent

.set CommandOffset,                       0
.set ApicIdOffset,                        0x4
.set WakeupVectorOffset,                  0x8

.set MpProtectedModeWakeupCommandNoop,    0
.set MpProtectedModeWakeupCommandWakeup,  1
.set MpProtectedModeWakeupCommandSleep,   2

.set MailboxApicIdInvalid,                0xffffffff
.set MailboxApicIdBroadcast,              0xfffffffe

.section .text

#--------------------------------------------------------------------
# ap_relocated_vector
#
# rbx:  Relocated mailbox address
# rbp:  vCpuId
#--------------------------------------------------------------------
.global ap_relocated_func
ap_relocated_func:
    mov         r8, rbx
    #
    # Get the APIC ID via CPUID
    mov         rax, 1
    cpuid
    shr         ebx, 24
    #
    # r8 will hold the APIC ID of current AP
    xchg        r8, rbx

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

.global ap_relocated_func_end
ap_relocated_func_end:
    jmp .panic
