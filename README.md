# TD-shim - Confidential Containers Shim Firmware

Hardware virtualization-based containers are designed to launch and run
containerized applications in hardware virtualized environments. While
containers usually run directly as bare-metal applications, using TD or VT as an
isolation layer from the host OS is used as a secure and efficient way of
building multi-tenant Cloud-native infrastructures (e.g. Kubernetes).

In order to match the short start-up time and resource consumption overhead of
bare-metal containers, runtime architectures for TD- and VT-based containers put
a strong focus on minimizing boot time. They must also launch the container
payload as quickly as possible. Hardware virtualization-based containers
typically run on top of simplified and customized Linux kernels to minimize the
overall guest boot time.

Simplified kernels typically have no UEFI dependencies and no ACPI ASL
support. This allows guests to boot without firmware dependencies. Current
VT-based container runtimes rely on VMMs that are capable of directly booting
into the guest kernel without loading firmware.

TD Shim is a simplified [TDX virtual firmware](doc/tdshim_spec#vfw) for the
simplified kernel for TD container. This document describes a lightweight
interface between the TD Shim and TD VMM and between the TD Shim and the
simplified kernel.

![Overview](doc/td-shim-diagram.png)

## Documents

* [Introduction (PDF)](doc/td-shim-introduction.pdf)
* [TD-Shim specification](doc/tdshim_spec.md)
