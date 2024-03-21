#!/bin/sh

echo "Adding IMA binaries"

. /usr/share/initramfs-tools/hook-functions

copy_exec /etc/keys/evm-key
copy_exec /etc/keys/kmk
copy_exec /etc/ima_policy
copy_exec /bin/keyctl
