#!/bin/bash

preparation() {
    # apply the patch set for ring
    pushd library/ring
    git reset --hard c3fda8b4dd57d658923c397c6cfaa33591f6f256
    git clean -f -d
    patch -p 1 -i ../patches/ring.diff
    popd
}

preparation
