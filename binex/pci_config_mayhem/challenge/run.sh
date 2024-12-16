#!/bin/sh

./libs_to_ship/ld-linux-x86-64.so.2 \
    --library-path ./libs_to_ship \
    ./qemu-system-x86_64 \
    -M accel=tcg \
    -L ./bios \
    -m 128 \
    -kernel bzImage \
    -drive file=rootfs.ext2,if=virtio,format=raw,snapshot=on \
    -append "rootwait root=/dev/vda console=ttyS0" \
    -device nite-pci \
    -sandbox on,spawn=deny \
    -display none \
    -serial stdio \

