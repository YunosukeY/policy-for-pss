#!/usr/bin/env bash

set -eu

version="v3.10.0"
repo_dir="$(git rev-parse --show-toplevel)"
bin="${repo_dir}/bin"
gator="${bin}/gator"

if [[ -x "${gator}" ]]; then
  true
else
  mkdir -p "${bin}"
  echo "download gator ${version}"
  url="https://github.com/open-policy-agent/gatekeeper/releases/download/${version}/gator-${version}-linux-amd64.tar.gz"
  curl -sfSLO "$url"
  tar -zxvf "gator-${version}-linux-amd64.tar.gz"
  mv gator "${bin}"
  chmod +x "${gator}"
fi

"${gator}" "${@}"
