#!/bin/bash

preparation() {
    # apply the patch set for ring
    pushd library/ring
    git reset --hard 464d367252354418a2c17feb806876d4d89a8508
    git clean -f -d
    patch -p 1 -i ../patches/ring.diff
    git apply ../patches/0001-NFC-Address-Clippy-unused-import-warning.patch
    popd
}

preparation
