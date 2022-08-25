#!/bin/bash

preparation() {
    # apply the patch set for ring
    pushd library/ring
    git reset --hard 9cc0d45f4d8521f467bb3a621e74b1535e118188
    git clean -f -d
    patch -p 1 -i ../patches/ring.diff
    popd
}

preparation
