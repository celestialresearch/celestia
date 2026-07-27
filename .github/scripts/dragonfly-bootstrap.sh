#!/usr/bin/env bash
# Copyright © 2026 @sudocelestia. All rights reserved.
#
# PROPRIETARY AND CONFIDENTIAL SOURCE CODE.
#
# No licence, permission or authorisation is granted to use, copy, modify,
# compile, execute, distribute, publish, sublicense or otherwise exploit this
# file, except to the limited extent unavoidably permitted by applicable law
# or GitHub's Terms of Service.
#
# See the LICENSE file at the repository root for the complete terms.

set -euo pipefail

retry() {
  local attempts=0
  until "$@"; do
    attempts=$((attempts + 1))
    if [[ "$attempts" -ge 3 ]]; then
      return 1
    fi
    sleep $((attempts * 5))
  done
}

if [[ "$(uname -s)" != DragonFly ]]; then
  echo 'DragonFly bootstrap requires DragonFly BSD' >&2
  exit 1
fi

repo_dir=/usr/local/etc/pkg/repos
default_repo="$repo_dir/df-latest.conf"
celestia_repo="$repo_dir/celestia.conf"
ca_bundle="$PWD/.github/generated/dragonfly-ca.pem"

if [[ ! -s "$ca_bundle" ]]; then
  echo 'DragonFly CA bundle is missing' >&2
  exit 1
fi

sudo mkdir -p "$repo_dir"
if [[ -f "$default_repo" ]]; then
  sudo mv "$default_repo" "$default_repo.disabled"
fi

sudo tee "$celestia_repo" >/dev/null <<'EOF'
Clarkson: {
    url: "https://mirror.clarkson.edu/dragonflybsd/${ABI}/LATEST",
    mirror_type: "NONE",
    enabled: yes
}
EOF

retry sudo env SSL_CA_CERT_FILE="$ca_bundle" pkg update -f
retry sudo env SSL_CA_CERT_FILE="$ca_bundle" pkg install -y go
