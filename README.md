# Cert Manager CRL Generator

Simple Kubernetes operator that generates CRL file for [Cert Manager] certificates issued by [CA] issuer.

This operator implementation is based on excellent Flant [Shell Operator].

## Usage

1. Put `cm-crl-generator.citc.dev/revoke: true` on desired certificate

See `k8s/example`.

## Development

### Prepare environment

Install [Aqua] and run `aqua i`. 

### Run in dev mode

Run Skaffold:

`skaffold dev`

### Release

Manual image build:

`docker build docker --label "git-commit=$(git rev-parse HEAD)" --tag ghcr.io/cit-consulting/cm-crl-generator:0.1`

[Cert Manager]: https://cert-manager.io
[CA]: https://cert-manager.io/docs/configuration/ca/
[Shell Operator]:  https://github.com/flant/shell-operator
[Aqua]: https://aquaproj.github.io
