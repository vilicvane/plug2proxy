#!/bin/bash

build=false
target=""

while getopts "t::m:c:d:b" flag; do
    case $flag in
    b)
        build=true
        ;;
    t)
        target=$OPTARG
        ;;
    m)
        mode=$OPTARG
        ;;
    c)
        resources=(${OPTARG//,/ })
        ;;
    d)
        destination=$OPTARG
        ;;
    ?)
        echo "Usage: [-t target] -m <mode> -c <resource,...> -d <destination> [-b]"
        exit 1
        ;;
    esac
done

if [ "$build" = true ]; then
    if [ -n "$target" ]; then
        cargo build --target $target --release
    else
        cargo build --release
    fi
fi

if [ -n "$target" ]; then
    target_path="target/$target/release"
else
    target_path="target/release"
fi

rsync --mkpath --verbose $target_path/plug2proxy $destination:/usr/sbin/

expanded_resources=()

for resource in "${resources[@]}"; do
    expanded_resources+=("res/$mode/$resource/./")
done

for resource in "${expanded_resources[@]}"; do
    rsync --recursive --relative --mkpath --verbose $resource $destination:/
done
