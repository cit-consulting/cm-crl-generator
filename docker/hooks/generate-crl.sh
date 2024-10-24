#!/usr/bin/env bash

if [[ $1 == "--config" ]] ; then
  cat lib/generate-crl.config.json
else
  # reconcile CA
  # cm-crl-generator.citc.dev/revoke = true
  echo implement me
  cmctl status certificate -n ns-1 cert-1
  #  cm-crl-generator.citc.dev/revoke = false
  # ouput secert <ca-name>-crl : tls.revoked-certs tls.crl
  # annotation: cm-crl-generator.citc.dev/ca-fingerprint
fi

exit 0
