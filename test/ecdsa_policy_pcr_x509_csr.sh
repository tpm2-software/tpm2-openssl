#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
set -eufx

PARENT_HANDLE=""
KEY_HANDLE=""

flush_ctx_object() {
    local want h
    want=$(tpm2_readpublic -c "$1" 2>/dev/null | sed -n 's/^name: //p') || true
    [ -n "$want" ] || return 0
    for h in $(tpm2_getcap handles-transient | sed -n 's/^- //p'); do
        if [ "$(tpm2_readpublic -c "$h" 2>/dev/null | sed -n 's/^name: //p')" = "$want" ]; then
            tpm2_flushcontext "$h"
        fi
    done
}

cleanup() {
    flush_ctx_object key.ctx || true
    flush_ctx_object primary.ctx || true
    if [ -n "$KEY_HANDLE" ]; then
        tpm2_evictcontrol -C o -c "$KEY_HANDLE" || true
    fi
    if [ -n "$PARENT_HANDLE" ]; then
        tpm2_evictcontrol -C o -c "$PARENT_HANDLE" || true
    fi
    rm -f primary.ctx key.pub key.priv key.ctx policy.digest eventdata \
          policy-test.csr policy-test-changed.csr
}
trap cleanup EXIT

tpm2_createprimary -C o -c primary.ctx
PARENT_HANDLE=$(tpm2_evictcontrol -C o -c primary.ctx | cut -d ' ' -f 2 | head -n 1)
flush_ctx_object primary.ctx
tpm2_createpolicy --policy-pcr -l sha256:0,1,7 -L policy.digest
tpm2_create -C "$PARENT_HANDLE" -G ecc -g sha256 \
    -a 'fixedtpm|fixedparent|sensitivedataorigin|sign' \
    -L policy.digest -u key.pub -r key.priv
tpm2_load -C "$PARENT_HANDLE" -u key.pub -r key.priv -c key.ctx
KEY_HANDLE=$(tpm2_evictcontrol -C o -c key.ctx | cut -d ' ' -f 2 | head -n 1)
flush_ctx_object key.ctx

openssl req -provider tpm2 -provider default -propquery '?provider=tpm2' \
    -new -subj '/CN=policy-test' -key "handle:${KEY_HANDLE}" \
    -sigopt 'policy-pcr:sha256:0,1,7' -out policy-test.csr
openssl req -in policy-test.csr -noout -verify

echo -n "policy-state-change" > eventdata
tpm2_pcrevent 7 eventdata

! openssl req -provider tpm2 -provider default -propquery '?provider=tpm2' \
    -new -subj '/CN=policy-test' -key "handle:${KEY_HANDLE}" \
    -sigopt 'policy-pcr:sha256:0,1,7' -out policy-test-changed.csr
! openssl req -in policy-test-changed.csr -noout -verify 2>/dev/null
