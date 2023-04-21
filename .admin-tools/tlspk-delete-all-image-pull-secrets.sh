#!/usr/bin/env bash

SCRIPT_NAME="tlspk-delete-all-image-pull-secrets.sh"
SCRIPT_VERSION="0.1"

: ${DEBUG:="false"}

log-info() {
  echo "${SCRIPT_NAME} [info]: $1"
}

log-error() {
  echo "${SCRIPT_NAME} [error]: $1" >&2
  return 1
}

finally() {
  exit_code=$?
  if [[ "$exit_code" != "0" ]]; then
    log-info "Aborting!"
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
    return 1
  fi
}

delete-all-image-pull-secrets() {
  log-info "Deleting all image pull secrets associated with your TLSPK organization ${TLSPK_ORG}"
  http_code=$(curl --no-progress-meter -L -w "%{http_code}" -o ${temp_dir}/image-pull-secrets.out \
    -X GET https://platform.jetstack.io/subscription/api/v1/org/${TLSPK_ORG}/svc_accounts \
    --header "authorization: Bearer ${TLSPK_ADMIN_TOKEN}")
  if grep -qv "^2" <<< ${http_code}; then
    log-error "https://platform.jetstack.io/subscription/api/v1/org/${TLSPK_ORG}/svc_accounts [GET] failed with HTTP status code ${http_code} and response '$(cat ${temp_dir}/image-pull-secrets.out)'"
    return 1
  fi
  image_pull_secrets=($(jq '.[].id' --raw-output < ${temp_dir}/image-pull-secrets.out))
  for image_pull_secret in "${image_pull_secrets[@]}"; do
    log-info "Deleting ${image_pull_secret}"
    pull_secret_request='[{"id":"'"${image_pull_secret}"'"}]'
    http_code=$(curl --no-progress-meter -L -w "%{http_code}" -o ${temp_dir}/image-pull-secret-${cluster}.out \
        -X DELETE https://platform.jetstack.io/subscription/api/v1/org/${TLSPK_ORG}/svc_accounts \
        --header "authorization: Bearer ${TLSPK_ADMIN_TOKEN}" \
        --data "${pull_secret_request}")
    if grep -qv "^2" <<< ${http_code}; then
      log-error "https://platform.jetstack.io/subscription/api/v1/org/${TLSPK_ORG}/svc_accounts [DELETE] failed with HTTP status code ${http_code} and response '$(cat ${temp_dir}/image-pull-secret-${cluster}.out)'"
      return 1
    fi
  done
}

# ----- MAIN -----
trap "finally" EXIT
set -eu

if [[ "${DEBUG}" == "true" ]]; then
  set -x
fi

temp_dir=$(mktemp -d)
check-vars
read -p "Deleting all images pull secrets associated with your TLSPK organization ${TLSPK_ORG}. This operation cannot be undone. Are you sure? [y/N] " APPROVED
if grep -qv "^y\|Y" <<< ${APPROVED}; then
  log-info "Operation not approved"
  exit 1
fi
delete-all-image-pull-secrets