;------------------------------------------------------------------------------
; @file
; Common macros used in the ResetVector VTF module.
;
; Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
;------------------------------------------------------------------------------

%macro tdcall 0
%if (USE_TDX_EMULATION != 0)
    vmcall
%else
    db 0x66,0x0f,0x01,0xcc
%endif
%endmacro


%define ADDR16_OF(x) (0x10000 - endOfResetVector + x)
%define ADDR_OF(x) (FW_TOP - endOfResetVector + x)

%macro  OneTimeCall 1
    jmp     %1
%1 %+ OneTimerCallReturn:
%endmacro

%macro  OneTimeCallRet 1
    jmp     %1 %+ OneTimerCallReturn
%endmacro


CommandOffset                             equ       00h
ApicidOffset                              equ       04h
WakeupVectorOffset                        equ       08h
OSArgsOffset                              equ       10h
FirmwareArgsOffset                        equ       800h
WakeupArgsRelocatedMailBox                equ       800h
ApWorkingStackStart                       equ       800h
PageTableBaseOffset                       equ       800h
IdtBaseOffset                             equ       800h
CpuArrivalOffset                          equ       900h
CpusExitingOffset                         equ       0a00h
TalliesOffset                             equ       0a08h

MpProtectedModeWakeupCommandNoop          equ       0
MpProtectedModeWakeupCommandWakeup        equ       1
MpProtectedModeWakeupCommandSleep         equ       2
MpProtectedModeWakeupCommandAssignWork    equ       3
MpProtectedModeWakeupCommandCheck         equ       4
MpProtectedModeWakeupCommandSetCr3        equ       5
MpProtectedModeWakeupCommandSetIdt        equ       6

MailboxApicIdInvalid                      equ       0xffffffff
MailboxApicidBroadcast                    equ       0xfffffffe

%macro simple_spinlock 3
    mov        edx, %1
    mov        eax, 0
    mov        ebx, 1
%%testlock:
    lock       cmpxchg [edx], ebx
    jnz        %3
    mov        eax, 0
    mov        ebx, 1
    lock       cmpxchg [edx+4], ebx
    jnz        %2
%%firstone:
    pause
%endmacro

%macro simple_releaselock 3
%2:
    mov        eax, 1
    mov        edx, %1
    jmp        %%testlock
%3:
    pause
    mov        eax, 0
%%testlock:
    mov        ebx, 0
    lock       cmpxchg [edx], ebx
    jnz        %3
%endmacro


%define PAGE_PRESENT            0x01
%define PAGE_READ_WRITE         0x02
%define PAGE_USER_SUPERVISOR    0x04
%define PAGE_WRITE_THROUGH      0x08
%define PAGE_CACHE_DISABLE     0x010
%define PAGE_ACCESSED          0x020
%define PAGE_DIRTY             0x040
%define PAGE_PAT               0x080
%define PAGE_GLOBAL           0x0100
%define PAGE_2M_MBO            0x080
%define PAGE_2M_PAT          0x01000

%define PAGE_2M_PDE_ATTR (PAGE_2M_MBO + \
                          PAGE_ACCESSED + \
                          PAGE_DIRTY + \
                          PAGE_READ_WRITE + \
                          PAGE_PRESENT)

%define PAGE_PDP_ATTR (PAGE_ACCESSED + \
                       PAGE_READ_WRITE + \
                       PAGE_PRESENT)

%define PT_ADDR(Base,Offset) ((Base) + (Offset))

%macro clear_pagetables 1
    mov     ecx, 6 * 0x1000 / 4
    xor     eax, eax
%%clearloop:
    mov     dword[ecx * 4 + PT_ADDR (%1,0) - 4], eax
    loop    %%clearloop
%endmacro

%macro init_l4_l3_page_tables 2
    ;
    ; Top level Page Directory Pointers (1 * 512GB entry)
    ;
    mov     dword[PT_ADDR (%1,0)], PT_ADDR (%1,0x1000) + PAGE_PDP_ATTR
    mov     dword[PT_ADDR (%1,4)], %2

    ;
    ; Next level Page Directory Pointers (4 * 1GB entries => 4GB)
    ;
    mov     dword[PT_ADDR (%1,0x1000)], PT_ADDR (%1,0x2000) + PAGE_PDP_ATTR
    mov     dword[PT_ADDR (%1,0x1004)], %2
    mov     dword[PT_ADDR (%1,0x1008)], PT_ADDR (%1,0x3000) + PAGE_PDP_ATTR
    mov     dword[PT_ADDR (%1,0x100C)], %2
    mov     dword[PT_ADDR (%1,0x1010)], PT_ADDR (%1,0x4000) + PAGE_PDP_ATTR
    mov     dword[PT_ADDR (%1,0x1014)], %2
    mov     dword[PT_ADDR (%1,0x1018)], PT_ADDR (%1,0x5000) + PAGE_PDP_ATTR
    mov     dword[PT_ADDR (%1,0x101C)], %2
%endmacro

%macro init_l2_page_tables 2
    ;
    ; Page Table Entries (2048 * 2MB entries => 4GB)
    ;
    mov     ecx, 0x800
%%loop:
    mov     eax, ecx
    dec     eax
    shl     eax, 21
    add     eax, PAGE_2M_PDE_ATTR
    mov     [ecx * 8 + PT_ADDR (%1,0x2000 - 8)], eax
    mov     dword[(ecx * 8 + PT_ADDR (%1,0x2000 - 8)) + 4], %2
    loop    %%loop
%endmacro

%macro initialize_page_tables 2
    clear_pagetables %1
    init_l4_l3_page_tables %1,%2
    init_l2_page_tables %1,%2
%endmacro


%define EFI_HOB_TYPE_HANDOFF              0x0001
%define EFI_HOB_TYPE_MEMORY_ALLOCATION    0x0002
%define EFI_HOB_TYPE_RESOURCE_DESCRIPTOR  0x0003
%define EFI_HOB_TYPE_GUID_EXTENSION       0x0004
%define EFI_HOB_TYPE_FV                   0x0005
%define EFI_HOB_TYPE_CPU                  0x0006
%define EFI_HOB_TYPE_MEMORY_POOL          0x0007
%define EFI_HOB_TYPE_FV2                  0x0009
%define EFI_HOB_TYPE_LOAD_PEIM_UNUSED     0x000A
%define EFI_HOB_TYPE_UEFI_CAPSULE         0x000B
%define EFI_HOB_TYPE_FV3                  0x000C
%define EFI_HOB_TYPE_UNUSED               0xFFFE
%define EFI_HOB_TYPE_END_OF_HOB_LIST      0xFFFF

%define EFI_RESOURCE_SYSTEM_MEMORY          0x00000000
%define EFI_RESOURCE_MEMORY_MAPPED_IO       0x00000001
%define EFI_RESOURCE_IO                     0x00000002
%define EFI_RESOURCE_FIRMWARE_DEVICE        0x00000003
%define EFI_RESOURCE_MEMORY_MAPPED_IO_PORT  0x00000004
%define EFI_RESOURCE_MEMORY_RESERVED        0x00000005
%define EFI_RESOURCE_IO_RESERVED            0x00000006
%define EFI_RESOURCE_MAX_MEMORY_TYPE        0x00000007

%define EFI_RESOURCE_ATTRIBUTE_PRESENT                  0x00000001
%define EFI_RESOURCE_ATTRIBUTE_INITIALIZED              0x00000002
%define EFI_RESOURCE_ATTRIBUTE_TESTED                   0x00000004
%define EFI_RESOURCE_ATTRIBUTE_READ_PROTECTED           0x00000080

%define EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE              0x00000400
%define EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE        0x00000800
%define EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE  0x00001000
%define EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE     0x00002000


%define EFI_IO_ATTR (EFI_RESOURCE_ATTRIBUTE_PRESENT + \
                          EFI_RESOURCE_ATTRIBUTE_INITIALIZED + \
                          EFI_RESOURCE_ATTRIBUTE_TESTED + \
                          EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE)

%define EFI_LOW_MEM_ATTR (EFI_RESOURCE_ATTRIBUTE_PRESENT + \
                          EFI_RESOURCE_ATTRIBUTE_INITIALIZED + \
                          EFI_RESOURCE_ATTRIBUTE_TESTED + \
                          EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE + \
                          EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE + \
                          EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE + \
                          EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE)

%define TDCALL_TDINFO                          0x1
%define TDCALL_TDACCEPTPAGE                    0x6
