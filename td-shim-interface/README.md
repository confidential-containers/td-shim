[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fconfidential-containers%2Ftd-shim.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fconfidential-containers%2Ftd-shim?ref=badge_shield)
# TD-shim-interface - Confidential Containers Shim Firmware Interface

## Documents

* [TD-Shim specification](https://github.com/confidential-containers/td-shim/tree/main/doc/tdshim_spec.md)

* Introduction [PDF](https://github.com/confidential-containers/td-shim/tree/main/doc/td-shim-introduction.pdf) and [conference talk](https://fosdem.org/2023/schedule/event/cc_online_rust/)

## Introduction

This td-shim-interface is to support user for creating data structures and functions required for td-shim, such as TdxMetadataDescriptor and TdxMetadataSection. 
Td-uefi-pi is used for UEFI Platform Initializaiton data structures and accessors.

To import the data structure of metadata, TD HOB and related function, such as:
```
use td_shim_interface::{TD_ACPI_TABLE_HOB_GUID, TD_E820_TABLE_HOB_GUID, TD_PAYLOAD_INFO_HOB_GUID}; 
use td_shim_interface::PayloadInfo; 
use td_shim_interface::acpi; 
use td_shim_interface::td_uefi_pi::{hob, pi, pi::guid}
```

This is a Shim Firmware to support [Intel TDX](https://software.intel.com/content/www/us/en/develop/articles/intel-trust-domain-extensions.html).

The API specification is at [td-shim specification](https://github.com/confidential-containers/td-shim/tree/main/doc/tdshim_spec.md).

The secure boot specification for td-shim is at [secure boot specification](https://github.com/confidential-containers/td-shim/tree/main/doc/secure_boot.md)

The design is at [td-shim design](https://github.com/confidential-containers/td-shim/tree/main/doc/design.md).

The threat model analysis is at [td-shim threat model](https://github.com/confidential-containers/td-shim/tree/main/doc/threat_model.md).


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fconfidential-containers%2Ftd-shim.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fconfidential-containers%2Ftd-shim?ref=badge_large)
