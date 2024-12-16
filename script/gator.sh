#!/usr/bin/env bash

set -eu

# renovate: datasource=github-releases depName=open-policy-agent/gatekeeper versioning=loose
readonly GATEKEEPER_VERSION="v3.19.0-beta.0"
readonly REPO_DIR="$(git rev-parse --show-toplevel)"
readonly BIN="${REPO_DIR}/BIN"
readonly GATOR="${BIN}/gator"

if [[ -x "${GATOR}" ]]; then
  true
else
  mkdir -p "${BIN}"
  echo "download gator ${GATEKEEPER_VERSION}"
  url="https://github.com/open-policy-agent/gatekeeper/releases/download/${GATEKEEPER_VERSION}/gator-${GATEKEEPER_VERSION}-linux-amd64.tar.gz"
  curl -sfSLO "$url"
  tar -zxvf "gator-${GATEKEEPER_VERSION}-linux-amd64.tar.gz"
  mv gator "${BIN}"
  chmod +x "${GATOR}"
fi

"${GATOR}" "${@}"
