#!/bin/sh

export DOCKER_BUILDKIT=1

DOCKER_BUILDX_PLATFORM="${DOCKER_BUILDX_PLATFORM:-linux/amd64}"
DOCKER_BUILDX_OUTPUT="${DOCKER_BUILDX_OUTPUT:---load}"
DOCKER_BUILDX_EXTRA_ARGS="${DOCKER_BUILDX_EXTRA_ARGS:-}"

RUST_VERSION="${RUST_VERSION:-"$(sed -n -E 's/^rust-version = "([^"]+)"$/\1/p' Cargo.toml)"}"

BUILD_DATE="${BUILD_DATE:-"$(date -u +"%Y-%m-%dT%TZ")"}"
GIT_COMMIT="${GIT_COMMIT:-"$(git rev-parse --short HEAD || echo "unknown")"}"
VERSION="${VERSION:-"$(sed -n -E 's/^version = "([^"]+)"$/\1/p' Cargo.toml)"}"

OCI_REGISTRY="${OCI_REGISTRY:-ghcr.io}"
OCI_REPOSITORY="${OCI_REPOSITORY:-opencast/octoka}"
OCI_TAG="${OCI_TAG:-"$VERSION"}"

docker buildx build \
  --pull \
  --platform "$DOCKER_BUILDX_PLATFORM" \
  $DOCKER_BUILDX_OUTPUT \
  $DOCKER_BUILDX_EXTRA_ARGS \
  \
  --build-arg DOCKER_BUILDX_PLATFORM="$DOCKER_BUILDX_PLATFORM" \
  --build-arg DOCKER_BUILDX_OUTPUT="$DOCKER_BUILDX_OUTPUT" \
  --build-arg DOCKER_BUILDX_EXTRA_ARGS="$DOCKER_BUILDX_EXTRA_ARGS" \
  --build-arg RUST_VERSION="$RUST_VERSION" \
  --build-arg BUILD_DATE="$BUILD_DATE" \
  --build-arg GIT_COMMIT="$GIT_COMMIT" \
  --build-arg VERSION="$VERSION" \
  -t "$OCI_REGISTRY/$OCI_REPOSITORY:latest" \
  -t "$OCI_REGISTRY/$OCI_REPOSITORY:dev" \
  -t "$OCI_REGISTRY/$OCI_REPOSITORY:$OCI_TAG" \
  .
