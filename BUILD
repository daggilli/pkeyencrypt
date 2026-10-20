#!/usr/bin/env bash
if [[ $# -ge 1 ]]; then
  TARGET="--target $1"
fi
cmake --build build $TARGET --config Debug -- -j$(nproc)

