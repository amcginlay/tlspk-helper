#!/usr/bin/env bash

: ${DEBUG:="false"}

finally() {
  result=$?
  if [ "$result" != "0" ]; then
    echo "aborting!"
  fi
  exit $result
}

function check_vars() {
  local result=0
  for var in "$@"; do
    if [[ -z "${!var}" ]]; then
      echo "$var is not set"
      result=1
    fi
  done
  return ${result}
}

help () {
  echo "Accepted environment variables are:"
  echo -e "\tCOMMAND              ->> select from get-oauth-token, get-dockerconfig"
  echo -e "\tTLSPK_SA_USER_ID     ->> The User ID of a TLSPK service account"
  echo -e "\tTLSPK_SA_USER_SECRET ->> The User Secret of a TLSPK service account"
}

function check-dependency() {
  command -v ${1} >/dev/null 2>&1 || {
    echo "missing dependency: ${1}"
    return 1
  }
}

function get-oauth-token() {
  local outfile=$(mktemp)
  local http_code=$(curl --no-progress-meter -L -w "%{http_code}" -o ${outfile} https://auth.jetstack.io/oauth/token \
    --data "audience=https://preflight.jetstack.io/api/v1" \
    --data "client_id=jmQwDGl86WAevq6K6zZo6hJ4WUvp14yD" \
    --data "grant_type=password" \
    --data "username=${TLSPK_SA_USER_ID}" \
    --data-urlencode "password=${TLSPK_SA_USER_SECRET}")
  cat ${outfile} && rm ${outfile}
  if grep -qv "^2" <<< ${http_code}; then return 127; fi
}

function derive-org-from-user() {
  export TLSPK_ORG=$(cut -d'@' -f2- <<< ${TLSPK_SA_USER_ID} | cut -d'.' -f1)
}

function get-secret-name() {
  echo "ips-$(hostname)-${TLSPK_SA_USER_ID}"
}

function create-secret() {
  local oauth_token_json=$(get-oauth-token)
  
  local oauth_token=$(jq .access_token --raw-output <<< ${oauth_token_json})
  local pull_secret_request='[{"id":"","displayName":"'"$(get-secret-name)"'"}]'
  local outfile=$(mktemp)
  local http_code=$(curl --no-progress-meter -L -w "%{http_code}" -o ${outfile} -X POST https://platform.jetstack.io/subscription/api/v1/org/${TLSPK_ORG}/svc_accounts \
    --header "authorization: Bearer ${oauth_token}" \
    --data ${pull_secret_request})
  cat ${outfile} && rm ${outfile}
  if grep -qv "^2" <<< ${http_code}; then return 127; fi
}

function get-config-dir() {
  echo "${HOME}/.tlspk/"
}

function get-secret-filename() {
  echo $(get-config-dir)$(get-secret-name).json
}

function get-secret() {
  local secret_filename=$(get-secret-filename)
  if ! [ -f ${secret_filename} ]; then
    if ! result=$(create-secret); then echo ${result}; return 126; fi
    mkdir $(get-config-dir)
    echo ${result} > ${secret_filename}
  fi
  cat ${secret_filename}
}

function extract-secret-data() {
  if ! result=$(get-secret); then echo ${result}; return 126; fi
  jq '.[0].key.privateData' --raw-output <<< ${result} | base64 --decode
}

function get-dockerconfig()
{
  local base64_switch=$(uname | grep -q Darwin && echo b || echo w)
  local pullsecret_file=$(mktemp)
  extract-secret-data > ${pullsecret_file}

  # despite documentation to the contrary, I don't believe "auths:eu.gcr.io:password" is required, so it's omitted
  local dockerconfigjson_file=$(mktemp)
  cat <<EOF > ${dockerconfigjson_file}
  {
    "auths": {
      "eu.gcr.io": {
        "username": "_json_key",
        "email": "auth@jetstack.io",
        "auth": "$(echo "_json_key:$(cat ${pullsecret_file})" | base64 -${base64_switch} 0)"
      }
    }
  }
EOF
cat ${dockerconfigjson_file} && rm ${dockerconfigjson_file} && rm ${pullsecret_file}
}

# main
trap "finally" EXIT
set -e

if [ "${DEBUG}" == "true" ]; then
  set -x
fi

check_vars "COMMAND" "TLSPK_SA_USER_ID" "TLSPK_SA_USER_SECRET"
check-dependency jq
derive-org-from-user
case ${COMMAND} in
  'get-oauth-token')
     get-oauth-token
     exit 0
     ;;
#   'extract-secret-data')
#      extract-secret-data
#      exit 0
#      ;;
  'get-dockerconfig')
     get-dockerconfig
     exit 0
     ;;
  *)
     echo "unknown COMMAND ${COMMAND}"
     help
     exit 1
     ;;
esac
