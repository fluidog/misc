#!/bin/sh
#label "immutable" files with EVM/IMA digital signatures
#label everything else with just EVM digital signatures

file $1 | grep 'ELF' > /dev/null
if [ $? -eq 0 ]; then
     #evmctl sign --imasig --key /etc/keys/privkey_evm.pem $1
     evmctl sign --imahash --key /etc/keys/privkey_evm.pem $1
else
     #evmctl sign --imahash --key /etc/keys/privkey_evm.pem $1
     head -n 1 $1 >/dev/null
fi