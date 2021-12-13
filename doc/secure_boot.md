# td-shim secure boot support

Secure boot in td-shim means the td-shim will verify the digital singature of the payload, beased upon a trusted anchor.
The payload includes the digital sigature and the public key. The td-shim includes a trust anchor - hash of public key.

For a TD wants to perform attestation for a payload image, there are two ways. 1) image digest, 2) image Secure Version Number (SVN). One major reason to drive this is to support SVN based attestation. See detail in Attestation section below.

## Signed Payload format

   We do not use [authenticode-PE](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) or [signed-module](https://www.kernel.org/doc/html/v4.15/admin-guide/module-signing.html) format, because X.509/PKCS7 is complicated and authenticode does not include SVN.

   We define below signed payload format:

   ```
      Header:
      +--------------------------+
      |   Type GUID              | <== Signed Payload {FCF2D558-9DF5-4F4D-B0D7-3E4B798AB066} (16 bytes)
      +--------------------------+
      |   Struct Version         | <== UINT32 (1)
      +--------------------------+
      |   Length                 | <== length Header + Payload (UINT32)
      +--------------------------+
      |   Payload Version        | <== UINT64
      +--------------------------+
      |   Payload SVN            | <== Secure Version Number (UINT64)
      +--------------------------+
      |   Signing Algorithm      | <== UINT32 (RSAPSS_3072+SHA384 = 1, ECDSA_NIST_P384+SHA384 = 2)
      +--------------------------+
      |   Reserved               | <== UINT32
      +--------------------------+

      Data:
      +--------------------------+
      |   Payload                |
      +--------------------------+

      Signature:
      +--------------------------+
      |   Signature Block        | <== {RSA_3072 Signature Block, ECDSA_NIST_P384 Signature Block}
      +--------------------------+

      Where RSA_3072 Signature Block is:
      +--------------------------+
      |   Public Mod (N)         | <== Mod (384 bytes)
      +--------------------------+
      |   Public Exponent (E)    | <== 0x010001 (8 bytes)
      +--------------------------+
      |   Signature              | <== Sign (Header||Payload) (384 bytes)
      +--------------------------+

      Where ECDSA_NIST_P384 Signature Block is: (NOTE: Not use ASN.1 encoding)
      +--------------------------+
      |   Public (X, Y)          | <== Public key (X: first 48 bytes, Y: second 48 bytes)
      +--------------------------+
      |   Signature (R, S)       | <== Sign (Header||Payload) (R: first 48 bytes, S: second 48 byts)
      +--------------------------+
   ```

## Trust Anchor in Td-Shim.

   The trust anchor is the hash of public key.

   We define below trust anchor in the Configuration Firmware Volume (CFV):

   ```
      CFV Header:
      +--------------------------+
      |   PI FV Header           | => EFI_FIRMWARE_FILE_SYSTEM3_GUID
      +--------------------------+
      +--------------------------+
      |   PI FFS Header          | => EFI_FV_FILETYPE_RAW, FileName(TrustAnchor) = {77A2742E-9340-4AC9-8F85-B7B978580021}
      +--------------------------+

      Data Header:
      +--------------------------+
      |   Type GUID              | <== Public Key Hash {BE8F65A3-A83B-415C-A1FB-F78E105E824E} (16 bytes)
      +--------------------------+
      |   Struct Version         | <== UINT32 (1)
      +--------------------------+
      |   Length                 | <== length of Data Header + Trust Anchor Data (UINT32)
      +--------------------------+
      |   Trust Anchor Algorithm | <== UINT32 (SHA384 = 1)
      +--------------------------+
      |   Reserved               | <== UINT32
      +--------------------------+

      Data:
      +--------------------------+
      |   Trust Anchor Data      | <== {SHA384 Block}
      +--------------------------+

      Where SHA384 Block is:
      +--------------------------+
      |   Hash Data              | <== hash of public key (RSA:N||E or ECDSA:X||Y) (48 bytes)
      +--------------------------+
   ```

## Build Time Enroll and Signature Generation

 * A `rust-tdshim-key-enroll` tool to enroll the public key hash to CFV.
 * A sample `rust-tdpayload-signing` tool to sign the payload image.

## Runtime Verification and Extension in td-shim

 * VMM/TDX Module extends the td-shim to MRTD.
 * td-shim extends Trust Anchor to RTMR[0], with event log.
 * td-shim verifies
    * CFV.TrustAnchorData == Hash(SignedPayload.SignatureBlock.PublicKey)
    * VerifySign(SignedPayload.Header||SignedPayload.Payload, SignedPayload.SignatureBlock) == TRUE
 * td-shim extends SignedPayload.Header.SVN to RTMR[1], with event log.
 * td-shim extends SignedPayload.Payload to RTMR[1], with event log.

## Attestation

### SVN based Payload Attestation

 * Verifier gets MRTD/RTMR and TD event log.
 * Verifier verifies td-shim image in MRTD.
 * Verifier verifies Trust Anchor in event log (RTMR[0]).
 * Verifier verifies Payload SVN in event log (RTMR[1]).

 We need enable secure boot to ensure the correctness of SVN.

### Digest based Payload Attestation

 * Verifier gets MRTD/RTMR and TD event log.
 * Verifier verifies td-shim image in MRTD.
 * Verifier verifies Payload image in event log (RTMR[1]).

 Secure boot is not needed in this case.

