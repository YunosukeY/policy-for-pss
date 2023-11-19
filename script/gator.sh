#!/usr/bin/env bash

set -eu

readonly VERSION="v3.14.0"
readonly REPO_DIR="$(git rev-parse --show-toplevel)"
readonly BIN="${REPO_DIR}/BIN"
readonly GATOR="${BIN}/gator"

if [[ -x "${GATOR}" ]]; then
  true
else
  mkdir -p "${BIN}"
  echo "download gator ${VERSION}"
  url="https://github.com/open-policy-agent/gatekeeper/releases/download/${VERSION}/gator-${VERSION}-linux-amd64.tar.gz"
  curl -sfSLO "$url"
  tar -zxvf "gator-${VERSION}-linux-amd64.tar.gz"
  mv gator "${BIN}"
  chmod +x "${GATOR}"
fi

"${GATOR}" "${@}"
