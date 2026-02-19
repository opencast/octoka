# syntax=docker/dockerfile:1.4

ARG RUST_VERSION

FROM docker.io/rust:${RUST_VERSION}-alpine AS dev-amd64
ARG RUST_TARGET=x86_64-unknown-linux-musl
ENV RUST_TARGET="$RUST_TARGET"

FROM docker.io/rust:${RUST_VERSION}-alpine AS dev-arm64
ARG RUST_TARGET=aarch64-unknown-linux-musl
ENV RUST_TARGET="$RUST_TARGET"

FROM dev-${TARGETARCH} AS build

RUN apk add --no-cache \
      make \
      musl-dev

RUN rustup target add "${RUST_TARGET}"

WORKDIR /build

# pre-build to cache dependencies in separate image layer
COPY Cargo.toml Cargo.lock /build/
COPY benches /build/benches
COPY <<EOF /build/src/main.rs
fn main() {}
EOF
RUN cargo build --target "${RUST_TARGET}" --release

# actual build
COPY . .
RUN touch /build/src/main.rs \
 && cargo build --target "${RUST_TARGET}" --release
RUN mkdir -p /rootfs \
 && cp "target/${RUST_TARGET}/release/octoka" /rootfs
RUN objcopy --compress-debug-sections /rootfs/octoka

# prepare deployment
RUN mkdir -p /rootfs/etc/octoka \
 && /rootfs/octoka gen-config-template > /rootfs/etc/octoka/config.toml \
 && sed -i '/\[http\]/,/^#address =.*$/ s/^#address =.*$/address = "0.0.0.0"/' /rootfs/etc/octoka/config.toml


FROM gcr.io/distroless/static:latest AS final
LABEL org.opencontainers.image.base.name="gcr.io/distroless/static:latest"

ARG BUILD_DATE=unknown \
    GIT_COMMIT=unknown \
    VERSION=unknown

LABEL maintainer="The Opencast project" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="The Opencast project" \
      org.opencontainers.image.url="ghcr.io/opencast/octoka" \
      org.opencontainers.image.documentation="https://github.com/opencast/octoka" \
      org.opencontainers.image.source="https://github.com/opencast/octoka" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.vendor="Opencast" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="octoka" \
      org.opencontainers.image.description="Opencast Token Authenticator"

COPY --from=build /rootfs /

USER nonroot
EXPOSE 4050
ENTRYPOINT [ "/octoka" ]
