;------------------------------------------------------------------------------
; @file
; Transition from 32 bit flat protected mode into 64 bit flat protected mode
;
; Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
;------------------------------------------------------------------------------

BITS    32

;
; Modified:  EAX. ECX
;
Transition32FlatTo64Flat:

    mov     eax, cr4
    bts     eax, 5                      ; enable PAE

    ;
    ; esp [6:0] holds gpaw, if it is at least 52 bits, need to set
    ; LA57 and use 5-level paging
    ;
    mov     ecx, esp
    and     ecx, 0x2f
    cmp     ecx, 52
    jl      .set_cr4
    bts     eax, 12
.set_cr4:
    mov     cr4, eax

    mov     ecx, ADDR_OF(TopLevelPageDirectory)
    ;
    ; if we just set la57, we are ok, if using 4-level paging, adjust top-level page directory
    ;
    bt      eax, 12
    jc      .set_cr3
    add     ecx, 0x1000
.set_cr3:
    mov     cr3, ecx

    mov     eax, cr0
    bts     eax, 31                     ; set PG
    mov     cr0, eax                    ; enable paging

    jmp     LINEAR_CODE64_SEL:ADDR_OF(jumpTo64BitAndLandHere)
BITS    64
jumpTo64BitAndLandHere:

    debugShowPostCode POSTCODE_64BIT_MODE

    OneTimeCallRet Transition32FlatTo64Flat
