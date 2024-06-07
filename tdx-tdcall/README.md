[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fconfidential-containers%2Ftd-shim.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fconfidential-containers%2Ftd-shim?ref=badge_shield)
# TDX-tdcall - Trust Domain Extensions tdcall

## Documents

* [Intel TDX](https://software.intel.com/content/www/us/en/develop/articles/intel-trust-domain-extensions.html)

## Introduction

Intel’s Trust Domain Extensions (TDX) protect confidential guest VMs from the host and physical attacks by isolating the guest register state and by encrypting the guest memory. In TDX, a special module running in a special mode sits between the host and the guest and manages the guest/host separation.

This tdx-tdcall crate provides constants, stuctures and wrappers to support user access TDCALL services.


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fconfidential-containers%2Ftd-shim.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fconfidential-containers%2Ftd-shim?ref=badge_large)
