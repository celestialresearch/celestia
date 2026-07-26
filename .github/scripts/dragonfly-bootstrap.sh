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

set -eu

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

sudo mkdir -p "$repo_dir"
if [[ -f "$default_repo" ]]; then
  sudo mv "$default_repo" "$default_repo.disabled"
fi

sudo tee "$repo_dir/celestia-auto.conf" >/dev/null <<'EOF'
AUTO: {
    url: "https://pkg.dragonflybsd.org/pkg/${ABI}/LATEST",
    mirror_type: "HTTP",
    enabled: yes
}
EOF

retry sudo pkg update -f
retry sudo pkg install -y go
