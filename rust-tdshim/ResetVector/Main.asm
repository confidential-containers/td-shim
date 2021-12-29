;------------------------------------------------------------------------------
; @file
; Main routine of the pre-SEC code up through the jump into SEC
;
; Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
;------------------------------------------------------------------------------


BITS    32

;
; Modified:  EBX, ECX, EDX, EBP, EDI, ESP
;
; @param[in,out]  RAX/EAX  0
; @param[in]      RFLAGS   2
; @param[in]      RCX      [31:0] TDINITVP - Untrusted Configuration
;                          [63:32] 0
; @param[in]      RDX      [31:0] VCPUID
;                          [63:32] 0
; @param[in]      RBX      [6:0] CPU supported GPA width
;                          [7:7] 5 level page table support
;                          [63:8] 0
; @param[in]      RSI      [31:0] VCPU_Index
;                          [63:32] 0
; @param[in]      RDI/EDI  0
; @param[in]      RBP/EBP  0
; @param[in/out]  R8       Same as RCX
; @param[out]     R9       [6:0] CPU supported GPA width
;                          [7:7] 5 level page table support
;                          [23:16] VCPUID
;                          [32:24] VCPU_Index
; @param[out]     R12,R13  SEC Core base (new), SEC Core size (new)
; @param[out]     RBP/EBP  Address of Boot Firmware Volume (BFV)
; @param[out]     DS       Selector allowing flat access to all addresses
; @param[out]     ES       Selector allowing flat access to all addresses
; @param[out]     FS       Selector allowing flat access to all addresses
; @param[out]     GS       Selector allowing flat access to all addresses
; @param[out]     SS       Selector allowing flat access to all addresses
;
; @return         None  This routine jumps to SEC and does not return
;
Main32:
    ; We need to preserve rdx and ebx information
    ; We are ok with rcx getting modified because copy is in r8, but will save in edi for now
    ; Save ecx in edi
    mov         edi, ecx

    ; Save ebx to esp
    mov         esp, ebx

    ; We need to store vcpuid/vcpu_index, we will use upper bits of ebx
    shl       esi, 16
    or        esp, esi

    ;
    ; Transition the processor from protected to 32-bit flat mode
    ;
    OneTimeCall ReloadFlat32

    ;
    ; Validate the Boot Firmware Volume (BFV)
    ;
    OneTimeCall Flat32ValidateBfv

    ;
    ; EBP - Start of BFV
    ;

    ;
    ; The SEC entry point

    mov edi, dword [TD_SHIM_RESET_SEC_CORE_BASE_ADDR]
    mov ebx, dword [TD_SHIM_RESET_SEC_CORE_SIZE_ADDR]
    mov esi, dword [TD_SHIM_RESET_SEC_CORE_ENTRY_POINT_ADDR]
    add esi, edi

    ;
    ; ESI - SEC Core entry point
    ; EBP - Start of BFV
    ; EDI - SEC Core base (new)
    ; EBX - SEC Core size (new)
    ;

    ;
    ; Transition the processor from 32-bit flat mode to 64-bit flat mode
    ;
    OneTimeCall Transition32FlatTo64Flat

BITS    64
    ; Save
    ; EDI - SEC Core base (new)
    ; EBX - SEC Core size (new)
    ; to R12 R13
    xor r12, r12
    xor r13, r13
    mov r12d, edi
    mov r13d, ebx

    mov r9, rsp
    ;
    ; Some values were calculated in 32-bit mode.  Make sure the upper
    ; 32-bits of 64-bit registers are zero for these values.
    ;
    mov     rax, 0x00000000ffffffff
    and     rsi, rax
    and     rbp, rax
    and     rsp, rax

    ;
    ; RSI - SEC Core entry point
    ; RBP - Start of BFV
    ;

    ;
    ; Restore initial EAX value into the RAX register
    ;
    mov     rax, 0

    ;
    ; Jump to the 64-bit SEC entry point
    ;
    ; jmp     rsi

; @param[in]      R8       [31:0] TDINITVP - Untrusted Configuration
;                          [63:32] 0
; @param[in]      R9       [6:0] CPU supported GPA width
;                          [7:7] 5 level page table support
;                          [23:16] VCPUID
;                          [32:24] VCPU_Index
; @param[in]      RBP      Pointer to the start of the Boot Firmware Volume

    ;
    ; Get vcpuid from r9, and determine if BSP
    ; APs jump to spinloop and get released by DXE's mpinitlib
    ;
    mov        rax, r9
    shr        rax, 16
    and        rax, 0xff
    test       rax, rax
    jne        ParkAp

    ; Fill the temporary RAM with the initial stack value (0x5AA55AA5).
    ; The loop below will seed the heap as well, but that's harmless.
    ;
    mov     rax, (0x5AA55AA5 << 32) | 0x5AA55AA5
                                                              ; qword to store
    mov     rdi, TEMP_STACK_BASE     ; base address
    mov     rcx, TEMP_STACK_SIZE / 8 ; qword count
    cld                                                       ; store from base
                                                              ;   up
    rep stosq

    ;
    ; Load temporary RAM stack based on PCDs
    ;
    %define SEC_TOP_OF_STACK (TEMP_STACK_BASE + TEMP_STACK_SIZE)
    mov     rsp, SEC_TOP_OF_STACK

    ; 1) Accept [1M, 1M + SEC Core Size]


    ; rcx = Accept address
    ; rdx = 0
    ; r8  = 0
    ;mov     rax, TDCALL_TDACCEPTPAGE
    ;tdcall

    mov     r14, 0x0                ; start address
    mov     r15, 0x800000           ; end address TBD

.accept_pages_for_sec_core_loop
    mov     r8,  0
    mov     rdx, 0
    mov     rcx, r14
    mov     rax, TDCALL_TDACCEPTPAGE
    tdcall

    add     r14, 0x1000
    cmp     r14, r15
    jne     .accept_pages_for_sec_core_loop


    ; 2) Copy [SEC Core Base, SEC Core Base+Size] to [1M, 1M + SEC Core Size]
    mov     rcx, r12
    mov     rdx, r12
    add     rdx, r13
    mov     r14, 0x100000

.copy_sec_core_loop
    mov     rax, qword [rcx]
    mov     qword [r14], rax
    add     r14, 0x8
    add     rcx, 0x8
    cmp     rcx, rdx
    jne     .copy_sec_core_loop

    ; 3) Fix RSI = RSI - SEC Core Base + 1M
    ; mov     r14, rsi
    ; sub     r14, r12
    ; add     r14, 0x100000
    ; mov     r12, r14
    sub     rsi, r12
    add     rsi, 0x100000
    nop

    ;
    ; Enable SSE and Write Protection
    ;
    mov     rax, cr0
    and     rax, 0xfffffffffffffffb     ; clear EM
    or      rax, 0x0000000000010002     ; set MP and Write Protection bit
    mov     cr0, rax
    mov     rax, cr4
    or      rax, 0x600                  ; set OSFXSR, OSXMMEXCPT
    mov     cr4, rax

    ;
    ; Setup parameters and call SecCoreStartupWithStack
    ;   rcx: BootFirmwareVolumePtr
    ;   rdx: TopOfCurrentStack
    ;   r8:  TdInitVp
    ;   r9:  gpaw/5-level-paging/vcpuid/vcpu_index
    ;
    mov     rcx, rbp
    mov     rdx, rsp
    sub     rsp, 0x20
    call    rsi

    ;
    ; Note, BSP never gets here, APs will be unblocked in DXE
    ;
ParkAp:

    ;
    ; Get vcpuid in rbp
    mov     rbp,  rax

    mov     rax, TDCALL_TDINFO
    tdcall
    ;
    ; R8  [31:0]  NUM_VCPUS
    ;     [63:32] MAX_VCPUS
    ; R9  [31:0]  VCPU_INDEX

    ;
    ; get the number of AP (r8d - 1)
    dec     r8d

.do_wait_loop:
    mov     rsp, TD_MAILBOX_BASE     ; base address

    mov     rax, 1
    lock xadd dword [rsp + CpuArrivalOffset], eax
    inc     eax

.check_arrival_cnt:
    cmp     eax, r8d
    je      .check_command
    mov     eax, dword[rsp + CpuArrivalOffset]
    jmp     .check_arrival_cnt

.check_command:
    mov     eax, dword[rsp + CommandOffset]
    cmp     eax, MpProtectedModeWakeupCommandNoop
    je      .check_command

    ; Determine if this is a broadcast or directly for my apic-id, if not, ignore
    cmp     dword[rsp + ApicidOffset], MailboxApicidBroadcast
    je      .mailbox_process_command
    cmp     dword[rsp + ApicidOffset], r9d
    jne     .check_command

.mailbox_process_command:
    cmp     eax, MpProtectedModeWakeupCommandWakeup
    je      .do_wakeup

    ;
    ; Check if the AP is available
    cmp     eax, MpProtectedModeWakeupCommandCheck
    je      .check_avalible

    cmp     eax, MpProtectedModeWakeupCommandAssignWork
    je      .set_ap_stack

    jmp     .check_command

.check_avalible
    ;
    ; Set the ApicId to be invalid to show the AP is available
    mov     dword[rsp + ApicidOffset], MailboxApicIdInvalid
    jmp     .check_command

.set_ap_stack
    ;
    ; Set the ApicId to be invalid to show the AP has been waked up
    mov     dword[rsp + ApicidOffset], MailboxApicIdInvalid
    ;
    ; Read the function address which will be called
    mov     eax, dword[rsp + WakeupVectorOffset]
    ;
    ; Read the stack address from arguments and set the rsp
    mov     rsp, [rsp + ApWorkingStackStart]
    ;
    ; CPU index as the first parameter
    mov     ecx, r9d
    ;
    ; r9d contains cpu index, which needs to be saved
    push    r9
    call    rax
    pop     r9

.do_finish_command:
    ;
    ;Set rsp back to TD_MAILBOX_BASE
    mov       rsp, TD_MAILBOX_BASE     ; base address
    mov       eax, 0FFFFFFFFh
    lock xadd dword [rsp + CpusExitingOffset], eax
    dec       eax

.check_exiting_cnt:
    cmp       eax, 0
    je        .check_command
    mov       eax, dword[rsp + CpusExitingOffset]
    jmp       .check_exiting_cnt

.do_wakeup:
    ;
    ; BSP sets these variables before unblocking APs
    mov     rax, 0
    mov     eax, dword[rsp + WakeupVectorOffset]
    mov     rbx, [rsp + WakeupArgsRelocatedMailBox]
    nop
    jmp     rax
    jmp     $
