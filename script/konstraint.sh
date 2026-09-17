#!/usr/bin/env bash

set -eu

# renovate: datasource=github-releases depName=plexsystems/konstraint versioning=loose
readonly KONSTRAINT_VERSION="v0.43.0"
readonly REPO_DIR="$(git rev-parse --show-toplevel)"
readonly BIN="${REPO_DIR}/bin"
readonly KONSTRAINT="${BIN}/konstraint"

if [[ -x "${KONSTRAINT}" ]]; then
  true
else
  mkdir -p "${BIN}"
  echo "download konstraint ${KONSTRAINT_VERSION}"
  url="https://github.com/plexsystems/konstraint/releases/download/${KONSTRAINT_VERSION}/konstraint-linux-amd64"
  curl -sfSL "$url" > "${KONSTRAINT}"
  chmod +x "${KONSTRAINT}"
fi

"${KONSTRAINT}" "${@}"
