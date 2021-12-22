# td-shim threat model and secure design

[TDX reference](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html)

## Trust Computing Base (TCB)


   ```
                   +--------------------------+  +================+  +----------------+
                   | +----------------------+ |  |                |  |                |
                   | |       td-payload     | |  |                |  |                |
                   | +----------------------+ |  |                |  |                |
                   |             ^            |  |   Legacy VM    |  |   Service TD   |
                   |             |            |  | (or) other TD  |  |  (or) Arch TD  |
                   | +----------------------+ |  |                |  |                |
                   | |        td-shim       | |  |                |  |                |
                   | +----------------------+ |  |                |  |                |
      Guest        +--------------------------+  +================+  +----------------+
      =====================================================================  ^  ==========
      Host           +----------------------+                                |
                     |      TDX-Module      |--------------------------------+
                     +----------------------+
                                ^
                                |
                     +======================+
                     |         VMM          |
                     +======================+

                     +----------------------+     +==============+
                     |       CPU SOC        |     |    Device    |
                     +----------------------+     +==============+

      Legend:
                     +--------------+   +==============+
                     |    In TCB    |   |  Out of TCB  |
                     +--------------+   +==============+

   ```

B-1. TDX-Module and its SOC CPU are trusted.

The result of TDCALL (except TDVMCALL) can be trusted.

B-2. Architecture TD or service TD is trusted.

The architecture TD and service TD SHALL support attestation.

B-3. VMM, Legacy VM or other user TD are not trusted.

The result of TDVMCALL cannot be trusted.

B-4. A device is not trusted.

There is no way to establish a secure relationship between a TD and a device in this generation.

## Integrity

I-1. Any input from VMM is NOT trusted, such as TD Hob, VMCALL result.

The input in the shared memory SHALL be copied to private memory before it been accessed.
The data SHALL be validated before use.

I-2. The device input is NOT trusted, such as VirtIO device, MMIO, IO, PCI, MSR, etc.

Same as I-1.

## Confidentiality

C-1. The TD SHALL use private memory whenever it is possible.

The shared memory is only used for VMM communication, or virtual device DMA.

C-2. The TD SHALL adopt all known side-channel mitigation.

reference:

[Intel Analysis of Speculative Execution Side Channels](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/analysis-speculative-execution-side-channels.html)

[Host Firmware Speculative Execution Side Channel Mitigation](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/host-firmware-speculative-side-channel-mitigation.html)

C-3. The TD SHALL follow best practice on cryptographic implementation.

reference:

[Cryptocoding](https://github.com/veorq/cryptocoding)

[Guidelines for Mitigating Timing Side Channels Against Cryptographic Implementations](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/secure-coding/mitigate-timing-side-channel-crypto-implementation.html)

[Intel Digital Random Number Generator (DRNG) Software Implementation Guide](https://www.intel.com/content/www/us/en/developer/articles/guide/intel-digital-random-number-generator-drng-software-implementation-guide.html)

## Availability

N/A

## Chain of Trust

T-1. The TD SHALL maintain a chain of trust and support attestation.

The component:(n) SHALL record the measurement and event log of the component:(n+1), before pass control to component:(n+1).

The TD configuration data from VMM SHALL be measured befure use.

T-2. The TD MAY use secure boot.

If secure boot is used, the component:(n) SHALL verify the component:(n+1), before pass control to component:(n+1).
The trust anchor of the verification SHALL be measured.

The TD SHALL consult the certificate revocation list (CRL) during verification, if CRL is present.
The CRL SHALL be measured.

The TD SHALL consider the secure version number (SVN) during verification, if SVN is present.
The SVN SHALL be measured.

## Defense in depth

P-1. The TD SHALL setup Data Execution Prevention (DEP).

All data page SHALL be Non-Executable (NX). All code page SHALL be read-only (RO). All rest page SHALL be not-present (NP).

It is illegal that a page has both execution and read-write.

P-2. The TD SHALL setup Control Flow Enforce Technology (CET).

If CET-Shadow Stack (SS) is supported, it SHALL be enabled.

if CET-Indirect Branch Tracking (IBT) is supported, it SHALL be enabled if it is supported by the compiler.

P-3. The TD SHALL support Address Space Layout Randomization. (ASLR).

The entropy of randomization can be determined by the use case.

reference:

[Intel 64 and IA-32 Architectures Software Developer Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)

[Data Execution Prevention](https://docs.microsoft.com/en-us/windows/win32/memory/data-execution-prevention)

[Arbitrary Code Execution](https://academic.microsoft.com/topic/2779004763)

[Control Flow Enforcement Technology](https://www.intel.com/content/www/us/en/developer/articles/technical/technical-look-control-flow-enforcement-technology.html)

[Address Space Layout Randomization](https://techcommunity.microsoft.com/t5/windows-security/turn-on-mandatory-aslr-in-windows-security/m-p/1186989)

[Mitigate threats by using Windows 10 security features](https://docs.microsoft.com/en-us/windows/security/threat-protection/overview-of-threat-mitigations-in-windows-10)

## Side Channel Attack Mitigation

S-1. The TD SHALL mitigate Spectre Variant 1 - Bounds Check Bypass.

The TD SHALL use LFENCE after validation of untrusted data but before use.

reference:

[Host Firmware Speculative Side Channel Mitigation](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/host-firmware-speculative-side-channel-mitigation.html)

