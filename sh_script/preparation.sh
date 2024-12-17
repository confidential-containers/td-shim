#!/bin/bash

preparation() {
    # apply the patch set for ring
    pushd library/ring
    git reset --hard 464d367252354418a2c17feb806876d4d89a8508
    git clean -f -d

    # apply the patch to get rid of unused import warning during compilation
    # https://github.com/briansmith/ring/commit/c4742e0cae849f08ff410a817c5266af41670b3d
    git cherry-pick c4742e0cae849f08ff410a817c5266af41670b3d

    patch -p 1 -i ../patches/ring.diff
    popd
}

preparation
