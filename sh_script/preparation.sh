#!/bin/bash

preparation() {
    # apply the patch set for ring
    pushd library/ring
    git reset --hard 2723abbca9e83347d82b056d5b239c6604f786df
    git clean -f -d
    git apply ../patches/ring.diff
    git apply ../patches/0002-Disable-checks-for-SSE-and-SSE2.patch
    popd
}

preparation
