;------------------------------------------------------------------------------
; @file
; This file includes all other code files to assemble the reset vector code
;
; Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
;------------------------------------------------------------------------------

%define ARCH_X64

%include "CommonMacros.inc"

StartOfResetVectorCode:

%define ADDR_OF_START_OF_RESET_CODE ADDR_OF(StartOfResetVectorCode)

%include "PostCodes.inc"
%include "X64/PageTables.asm"

%ifdef DEBUG_PORT80
  %include "Port80Debug.asm"
%elifdef DEBUG_SERIAL
  %include "SerialDebug.asm"
%else
  %include "DebugDisabled.asm"
%endif

%include "Ia32/ValidateBfvBase.asm"
%include "Ia32/Flat32ToFlat64.asm"
%include "Ia32/ReloadFlat32.asm"

%include "Main.asm"

%include "Ia32/ResetVectorVtf0.asm"
