#!/usr/bin/env bash

SCRIPT_NAME="tlspk-disconnect-all-clusters.sh"
SCRIPT_VERSION="0.1"

: ${DEBUG:="false"}

log-info() {
  echo "${SCRIPT_NAME} [info]: $1"
}

log-error() {
  echo "${SCRIPT_NAME} [error]: $1" >&2
  exit 1 # no need to hang around
}

finally() {
  exit_code=$?
  if [[ "$exit_code" != "0" ]]; then
    log-info "aborting!"
  fi
  rm -rf ${temp_dir}
  exit $exit_code
}

check-vars() {
  required_vars=("TLSPK_ORG" "TLSPK_ADMIN_TOKEN")
  missing_vars=()
  for var in "${required_vars[@]}"; do
    if [[ -z "${!var}" ]]; then
      missing_vars+=("$var")
    fi
  done
  if [[ ${#missing_vars[@]} -ne 0 ]]; then
    log-error "the following REQUIRED environment variables are missing: ${missing_vars[*]}"
  fi
}

# DON'T DELETE THIS UNTIL IT'S GRAFTED ACROSS TO tlspk-helper
# Q. SHOULD WE PASS CONTENTS OF ${temp_dir}/token.out TO log-error ??? also same for disconnect-all-clusters
# get-oauth-token() {
#   http_code=$(curl --no-progress-meter -L -w "%{http_code}" -o ${temp_dir}/token.out \
#     -X POST https://auth.jetstack.io/oauth/token \
#     --data "audience=https://preflight.jetstack.io/api/v1" \
#     --data "client_id=jmQwDGl86WAevq6K6zZo6hJ4WUvp14yD" \
#     --data "grant_type=password" \
#     --data "username=${TLSPK_SA_USER_ID}" \
#     --data-urlencode "password=${TLSPK_SA_USER_SECRET}")
#   if grep -qv "^2" <<< ${http_code}; then log-error "https://auth.jetstack.io/oauth/token [POST] failed with HTTP status code ${http_code}"; fi
#   cat ${temp_dir}/token.out
# }

disconnect-all-clusters() {
  log-info "Diconnecting all clusters from ${TLSPK_ORG}"
  http_code=$(curl --no-progress-meter -L -w "%{http_code}" -o ${temp_dir}/clusters.out \
    -X GET https://platform.jetstack.io/api/v1/org/${TLSPK_ORG}/clusters \
    --header "authorization: Bearer ${TLSPK_ADMIN_TOKEN}")
  if grep -qv "^2" <<< ${http_code}; then log-error "https://platform.jetstack.io/api/v1/org/${TLSPK_ORG}/clusters [GET] failed with HTTP status code ${http_code}"; fi
  clusters=($(jq '.[].cluster' --raw-output < ${temp_dir}/clusters.out))
  for cluster in "${clusters[@]}"; do
    log-info "Deleting ${cluster}"
    http_code=$(curl --no-progress-meter -L -w "%{http_code}" -o ${temp_dir}/deletion-${cluster}.out \
        -X DELETE https://platform.jetstack.io/api/v1/org/${TLSPK_ORG}/clusters/${cluster} \
        --header "authorization: Bearer ${TLSPK_ADMIN_TOKEN}")
    cat ${temp_dir}/deletion-${cluster}.out
    if grep -qv "^2" <<< ${http_code}; then log-error "https://platform.jetstack.io/api/v1/org/${TLSPK_ORG}/clusters/${cluster} [DELETE] failed with HTTP status code ${http_code}"; fi
  done
}

# ----- MAIN -----
trap "finally" EXIT
set -e

if [[ "${DEBUG}" == "true" ]]; then
  set -x
fi

temp_dir=$(mktemp -d)
check-vars
read -p "Removing ALL clusters from your TLSPK organization (${TLSPK_ORG}). This operation cannot be undone. Are you sure? [y/N] " APPROVED
if grep -qv "^y\|Y" <<< ${APPROVED}; then
  log-info "Operation not approved"
  exit 1
fi
disconnect-all-clusters