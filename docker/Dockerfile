FROM ghcr.io/flant/shell-operator:v1.5.1

RUN apk --no-cache add gnutls-utils

ADD --chmod=0755 https://github.com/cert-manager/cmctl/releases/download/v2.1.1/cmctl_linux_amd64 /bin/cmctl

RUN adduser -S controller

RUN chown -R controller "/hooks" &&  \
    mkdir /var/run/shell-operator &&  \
    chown -R controller "/var/run/shell-operator"

USER controller

COPY hooks /hooks
