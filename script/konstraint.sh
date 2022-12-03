#!/usr/bin/env bash

set -eu

version="v0.24.0"
repo_dir="$(git rev-parse --show-toplevel)"
bin="${repo_dir}/bin"
konstraint="${bin}/konstraint"

if [[ -x "${konstraint}" ]]; then
  true
else
  mkdir -p "${bin}"
  echo "download konstraint ${version}"
  url="https://github.com/plexsystems/konstraint/releases/download/${version}/konstraint-linux-amd64"
  curl -sfSL "$url" > "${konstraint}"
  chmod +x "${konstraint}"
fi

"${konstraint}" "${@}"
