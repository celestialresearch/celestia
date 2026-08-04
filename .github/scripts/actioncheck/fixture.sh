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

action_test_root=${CELESTIA_VERIFICATION_ROOT:-$(
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd
)}

new_action_test_work() {
  work_dir=$(mktemp -d "${TMPDIR:-/tmp}/celestia-actioncheck.XXXXXX")
  currency_file="$work_dir/currency"
  currency_script="$work_dir/currencycheck.sh"
  module_file="$work_dir/go.mod"
  module_sum_file="$work_dir/go.sum"
  cache_root="$work_dir/cache"

  export ACTIONCHECK_CURRENCY_FILE=$currency_file
  export ACTIONCHECK_CURRENCY_SCRIPT=$currency_script
  export ACTIONCHECK_MODULE_FILE=$module_file
  export ACTIONCHECK_MODULE_SUM_FILE=$module_sum_file
  export CELESTIA_CACHE_DIR=$cache_root

  printf 'fixture\n' >"$currency_file"
  printf '#!/usr/bin/env bash\nexit 1\n' >"$currency_script"
  printf 'module\n' >"$module_file"
  printf 'sum\n' >"$module_sum_file"

  # shellcheck source=.github/scripts/actioncheck.sh
  source "$action_test_root/.github/scripts/actioncheck.sh"
}
