;------------------------------------------------------------------------------
; @file
; Emits Page Tables for 1:1 mapping of the addresses 0 - 0x100000000 (4GB)
;
; Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
;------------------------------------------------------------------------------

KvmTestHob:
  DW EFI_HOB_TYPE_HANDOFF
  DW 0x38
  DD 0
  DD 9
  DD 0 ; boot-mode
  DQ 0
  DQ 0
  DQ 0
  DQ 0
  DQ ADDR_OF(KvmTestHobEnd)
  DW EFI_HOB_TYPE_GUID_EXTENSION
  DW 0x1c
  DD 0
  ; 0xc4a567a3, 0xc8a5, 0x44ea, 0xac, 0x78, 0xa4, 0xc3, 0x8b, 0x85, 0x49, 0xd0 Name
  DD 0xc4a567a3
  DW 0xc8a5, 0x44ea
  DB 0xac, 0x78, 0xa4, 0xc3, 0x8b, 0x85, 0x49, 0xd0
  DD 0 ; Feature
  DW EFI_HOB_TYPE_RESOURCE_DESCRIPTOR
  DW 0x30
  DD 0
  TIMES 16 DB 0 ; Owner
  DD EFI_RESOURCE_SYSTEM_MEMORY ; ResourceType
  DD EFI_LOW_MEM_ATTR ; ResourceAttribute
  DQ 0x100000 ; PhysicalStart
  DQ 0x7FF00000 ; ResourceLength
  DW EFI_HOB_TYPE_RESOURCE_DESCRIPTOR
  DW 0x30
  DD 0
  TIMES 16 DB 0 ; Owner
  DD EFI_RESOURCE_SYSTEM_MEMORY ; ResourceType
  DD EFI_LOW_MEM_ATTR ; ResourceAttribute
  DQ 0x0 ; PhysicalStart
  DQ 0xa0000 ; ResourceLength
  DW EFI_HOB_TYPE_RESOURCE_DESCRIPTOR
  DW 0x30
  DD 0
  TIMES 16 DB 0 ; Owner
  DD EFI_RESOURCE_SYSTEM_MEMORY ; ResourceType
  DD EFI_LOW_MEM_ATTR ; ResourceAttribute
  DQ 0x1a00000000 ; PhysicalStart
  DQ 0x80000000 ; ResourceLength
  DW EFI_HOB_TYPE_END_OF_HOB_LIST
  DW 0x08
  DD 0
KvmTestHobEnd:
