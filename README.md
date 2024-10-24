# Cert Manager CRL Generator

Simple Kubernetes operator that generates CRL file for [Cert Manager] certificates issued by [CA] issuer.

## Usage

1. Put `cm-crl-generator.citc.dev/revoke: true` on desired certificate

See `k8s/example`.

## Development

Run Skaffold:

`skaffold dev --port-forward`

Manual image build:

`docker build docker --label "git-commit=$(git rev-parse HEAD)" --tag ghcr.io/cit-consulting/cm-crl-generator:0.1`

This operator implementation is based on excellent Flant [Shell Operator].

[Cert Manager]: https://cert-manager.io
[CA]: https://cert-manager.io/docs/configuration/ca/
[Shell Operator]:  https://github.com/flant/shell-operator
