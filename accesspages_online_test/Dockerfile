ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.22
FROM golang:1.26-bookworm AS protocol-build

ARG OPENNHP_COMMIT=819e1b31e8ad0f028fe1de41789d8bd6c5f1cd6d
ARG NHP_FRP_COMMIT=2d9ad7d6fa0609fd973606b4b898e71c33854e0f
WORKDIR /build
RUN git clone https://github.com/OpenNHP/opennhp.git core \
    && git -C core checkout --detach "${OPENNHP_COMMIT}" \
    && git clone https://github.com/OpenNHP/nhp-frp.git frp \
    && git -C frp checkout --detach "${NHP_FRP_COMMIT}"

COPY nhp/native-payload-logging.patch nhp/patch-payload-logging.sh /build/
RUN sh /build/patch-payload-logging.sh /build/core
COPY nhp/main.go /build/core/endpoints/accesspages_online_test/main.go
RUN cd /build/core/endpoints \
    && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' \
       -o /out/machinectl ./accesspages_online_test

RUN cd /build/frp \
    && go mod edit \
       -replace github.com/OpenNHP/opennhp/nhp=/build/core/nhp \
       -replace github.com/OpenNHP/opennhp/endpoints=/build/core/endpoints \
    && go mod tidy \
    && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' \
       -o /out/frpc ./cmd/frpc

FROM ${BUILD_FROM}

ARG BUILD_ARCH=amd64
ARG BUILD_VERSION=0.1.0-beta.19
LABEL io.hass.type="addon" io.hass.arch="${BUILD_ARCH}" io.hass.version="${BUILD_VERSION}" \
      io.hass.name="Access Pages Online test" org.opencontainers.image.source="https://github.com/AZDane/accesspages-online-app"
RUN apk add --no-cache ca-certificates nginx openssl py3-cryptography python3 tini \
    && addgroup -g 2000 access-pages \
    && addgroup -g 2001 access-workers \
    && addgroup -g 2002 access-frontend \
    && for entry in admin:1001 broker:1003 tls:1004 connector:1005; do \
         addgroup -g "${entry#*:}" "access-${entry%:*}" \
         && adduser -D -H -u "${entry#*:}" -G "access-${entry%:*}" "access-${entry%:*}" || exit 1; \
       done
COPY --from=protocol-build /out/machinectl /opt/machinectl
COPY --from=protocol-build /out/frpc /opt/frpc
COPY rootfs /
RUN printf '%s\n' "${BUILD_VERSION}" > /opt/accesspages-test/version
RUN chmod 0755 /opt/machinectl /opt/frpc /opt/accesspages-test/runtime.py \
    && find /opt/accesspages-test -type d -exec chmod 0755 {} \; \
    && find /opt/accesspages-test -type f -exec chmod 0644 {} \;

ENTRYPOINT ["/sbin/tini", "-s", "--"]
CMD ["python3", "/opt/accesspages-test/runtime.py"]
