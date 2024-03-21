#!/bin/sh -e

PREREQ=""

# Output pre-requisites
prereqs()
{
        echo "$PREREQ"
}

case "$1" in
    prereqs)
        prereqs
        exit 0
        ;;
esac

grep -q "ima=off" /proc/cmdline && exit 1

mount -n -t securityfs securityfs /sys/kernel/security


# import EVM HMAC key
keyctl add user kmk "load $(cat /etc/keys/kmk)" @u
keyctl add encrypted evm-key "load $(cat /etc/keys/evm-key)" @u
#keyctl revoke kmk


# import IMA public key
# ima_id=`keyctl newring _ima @u`
# evmctl import --rsa /etc/keys/pubkey_ima.pem $ima_id

# import EVM public key
evm_id=`keyctl newring _evm @u`
evmctl import --rsa /etc/keys/pubkey_evm.pem $evm_id

# enable EVM
echo "1" > /sys/kernel/security/evm