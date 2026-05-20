#!/bin/bash
# Copyright (c) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# End-to-end test: full custom image build pipeline.
#
# Pipeline:
#   1. Build td-shim + example payload (initial build)
#   2. td-shim-image-layout-gen (compute layout from artifacts)
#   3. Rebuild td-shim with generated layout (cargo image --layout)
#   4. td-shim-metadata-gen (generate TDX metadata JSON)
#   5. td-shim-ld (link final image with custom metadata)
#   6. td-shim-checker (validate final image)
#   7. td-shim-patch tdx-metadata (patch NRX signature)
#
# This validates the full custom image workflow described in doc/custom_nrx_image.md.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${PROJECT_ROOT}/target/e2e-test"

echo "=== Custom NRX Image Build Pipeline ==="
echo "Project root: ${PROJECT_ROOT}"
mkdir -p "${OUTPUT_DIR}"

# --- Step 1: Initial build ---
echo ""
echo "--- Step 1: Build td-shim + example payload ---"

cargo image --example-payload --release

PAYLOAD="${PROJECT_ROOT}/target/x86_64-unknown-none/release/example"
IPL="${PROJECT_ROOT}/target/x86_64-unknown-none/release/td-shim"
RESET_VECTOR="${PROJECT_ROOT}/target/x86_64-unknown-none/release/ResetVector.bin"

for f in "${PAYLOAD}" "${IPL}" "${RESET_VECTOR}"; do
    if [[ ! -f "${f}" ]]; then
        echo "ERROR: Required artifact not found: ${f}"
        exit 1
    fi
done
echo "PASS: All build artifacts present"

# --- Step 2: Compute image layout ---
echo ""
echo "--- Step 2: td-shim-image-layout-gen ---"
echo "  This step measures actual binary sizes and computes the full layout"
echo "  including ImageSize (sum of all sections, 4K-aligned)."

# Create a layout template with all optional fields included.
# Payload, Ipl, ResetVector, and ImageSize will be overridden by the tool
# based on actual artifact sizes.
cat > "${OUTPUT_DIR}/layout_template.json" <<'EOF'
{
    "Config": "0x40000",
    "Mailbox": "0x1000",
    "TdParams": "0x1000",
    "TempStack": "0x20000",
    "TempHeap": "0x20000",
    "TdInfo": "0x1000",
    "Metadata": "0x1000",
    "Payload": "0x0",
    "Ipl": "0x0",
    "ResetVector": "0x0"
}
EOF

cargo run -p td-shim-tools --bin td-shim-image-layout-gen -- \
    --project-root "${PROJECT_ROOT}" \
    --payload-binary example \
    --cargo-build-directory release \
    --template "${OUTPUT_DIR}/layout_template.json" \
    --output "${OUTPUT_DIR}/image_layout.generated.json"

if [[ ! -f "${OUTPUT_DIR}/image_layout.generated.json" ]]; then
    echo "FAIL: td-shim-image-layout-gen did not produce output"
    exit 1
fi
echo "PASS: Generated ${OUTPUT_DIR}/image_layout.generated.json"
cat "${OUTPUT_DIR}/image_layout.generated.json"

# --- Step 3: Rebuild td-shim with generated layout ---
echo ""
echo "--- Step 3: Rebuild td-shim with generated layout (via cargo image) ---"

# cargo image --layout handles: td-layout-config -> rebuild -> strip -> link
# We use it here to rebuild with the computed layout. This also produces a final
# image, but we'll produce our own in Step 5 using the metadata-gen output.
cargo image --example-payload --release \
    --layout "${OUTPUT_DIR}/image_layout.generated.json" \
    -o "${OUTPUT_DIR}/final-via-cargo-image.bin"

echo "PASS: td-shim rebuilt with custom layout"

# --- Step 4: Generate TDX metadata ---
echo ""
echo "--- Step 4: td-shim-metadata-gen ---"

cargo run -p td-shim-tools --bin td-shim-metadata-gen -- \
    --layout "${OUTPUT_DIR}/image_layout.generated.json" \
    --memory-layout "${PROJECT_ROOT}/td-shim-tools/etc/sample_nrx_physical_memory.json" \
    --out "${OUTPUT_DIR}/metadata.json"

if [[ ! -f "${OUTPUT_DIR}/metadata.json" ]]; then
    echo "FAIL: td-shim-metadata-gen did not produce output"
    exit 1
fi
echo "PASS: Generated ${OUTPUT_DIR}/metadata.json"

# --- Step 5: Link final image with custom metadata ---
echo ""
echo "--- Step 5: td-shim-ld (link final image) ---"

cargo run -p td-shim-tools --bin td-shim-ld --features linker -- \
    "${PROJECT_ROOT}/target/x86_64-unknown-none/release/ResetVector.bin" \
    "${PROJECT_ROOT}/target/x86_64-unknown-none/release/td-shim" \
    -m "${OUTPUT_DIR}/metadata.json" \
    -p "${PROJECT_ROOT}/target/x86_64-unknown-none/release/example" \
    -o "${OUTPUT_DIR}/final-custom.bin"

if [[ ! -f "${OUTPUT_DIR}/final-custom.bin" ]]; then
    echo "FAIL: td-shim-ld did not produce final image"
    exit 1
fi
echo "PASS: Final image at ${OUTPUT_DIR}/final-custom.bin"
ls -lh "${OUTPUT_DIR}/final-custom.bin"

# --- Step 6: Validate with td-shim-checker ---
echo ""
echo "--- Step 6: Validate final image ---"

cargo run -p td-shim-tools --bin td-shim-checker --no-default-features --features=loader -- \
    "${OUTPUT_DIR}/final-custom.bin"

echo "PASS: td-shim-checker validated final image"

# --- Step 7: Patch NRX metadata signature ---
echo ""
echo "--- Step 7: td-shim-patch tdx-metadata (NRX signature) ---"

cargo run -p td-shim-tools --bin td-shim-patch -- tdx-metadata \
    --in "${OUTPUT_DIR}/final-custom.bin" \
    --out "${OUTPUT_DIR}/final-custom.bin" \
    --signature 0x58524E5F

echo "PASS: Patched metadata signature to 0x58524E5F (_NRX)"

# # --- (Optional) Patch TD_PARAMS and TD_INFO ---
# cargo run -p td-shim-tools --bin td-shim-patch -- td-params \
#     --in "${OUTPUT_DIR}/final-custom.bin" \
#     --out "${OUTPUT_DIR}/final-custom.bin" \
#     --tdparams td-shim-tools/etc/sample_td_params.json
#
# cargo run -p td-shim-tools --bin td-shim-patch -- td-info \
#     --in "${OUTPUT_DIR}/final-custom.bin" \
#     --out "${OUTPUT_DIR}/final-custom.bin" \
#     --guid ffffffff-ffff-ffff-ffff-ffffffffffff \
#     --version 1.0.0 \
#     --svn 1 \
#     --payload-info path/to/nrx_info.bin

# --- Restore original layout ---
echo ""
echo "--- Restoring original td-layout source ---"
pushd "${PROJECT_ROOT}" > /dev/null
git checkout -- td-layout/src/ 2>/dev/null || true
popd > /dev/null

# --- Cleanup ---
rm -rf "${OUTPUT_DIR}"

echo ""
echo "=== All Custom NRX Image Build Pipeline steps passed ==="
