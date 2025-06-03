#!/bin/bash

command="cargo"
target=""

while getopts "t::m:r::d:" flag; do
    case $flag in
    t)
        target=$OPTARG
        command="cross"
        ;;
    m)
        mode=$OPTARG
        ;;
    r)
        resources=(${OPTARG//,/ })
        ;;
    d)
        destination=$OPTARG
        ;;
    ?)
        echo "Usage: [-t target] -m <mode> -r <resource,...> -d <destination>"
        exit 1
        ;;
    esac
done

if [ -n "$target" ]; then
    $command build --target $target --release
else
    $command build --release
fi

if [ -n "$target" ]; then
    target_path="target/$target/release"
else
    target_path="target/release"
fi

rsync --mkpath --times --verbose $target_path/plug2proxy $destination:/usr/sbin/

expanded_resources=()

for resource in "${resources[@]}"; do
    expanded_resources+=("res/$mode/$resource/./")
done

for resource in "${expanded_resources[@]}"; do
    rsync --recursive --relative --mkpath --times --verbose $resource $destination:/
done
