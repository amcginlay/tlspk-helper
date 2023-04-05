#!/usr/bin/env bash

# TODO
# 1) TLSPK_CLUSTER_NAME must be less than 32 chars
# 2) make deploy-operator-components depend upon install-operator
# 3) provide an example curl command in the help output

: ${DEBUG:="false"}
: ${COMMAND:="help"}
: ${TLSPK_CLUSTER_NAME:=$(hostname)-$(date +"%y%m%d%H%M")}

BASE64_WRAP_SWITCH=$(uname | grep -q Darwin && echo b || echo w)

function logger(){
  echo "tlspk-helper.sh: $1"
}

finally() {
  local result=$?
  if [ "$result" != "0" ]; then
    echo "aborting!"
  fi
  exit $result
}

check-vars() {
  local result=0
  for var in "$@"; do
    if [[ -z "${!var}" ]]; then
      echo "$var is not set"
      result=1
    fi
  done
  return ${result}
}

check-dependency() {
  command -v ${1} >/dev/null 2>&1 || {
    echo "missing dependency: ${1}"
    return 1
  }
}

get-oauth-token() {
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

derive-org-from-user() {
  export TLSPK_ORG=$(cut -d'@' -f2- <<< ${TLSPK_SA_USER_ID} | cut -d'.' -f1)
}

get-secret-name() {
  echo "ips-$(hostname)-${TLSPK_SA_USER_ID}"
}

create-secret() {
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

get-config-dir() {
  echo "${HOME}/.tlspk/"
}

get-secret-filename() {
  echo $(get-config-dir)$(get-secret-name).json
}

get-secret() {
  local secret_filename=$(get-secret-filename)
  if ! [ -f ${secret_filename} ]; then
    if ! result=$(create-secret); then echo ${result}; return 126; fi
    mkdir $(get-config-dir)
    echo ${result} > ${secret_filename}
  fi
  cat ${secret_filename}
}

extract-secret-data() {
  if ! result=$(get-secret); then echo ${result}; return 126; fi
  jq '.[0].key.privateData' --raw-output <<< ${result} | base64 --decode
}

get-dockerconfig()
{
  local pullsecret_file=$(mktemp)
  extract-secret-data > ${pullsecret_file}

  # despite documentation to the contrary, I don't believe "auths:eu.gcr.io:password" is required, so it's omitted
  local dockerconfigjson_file=$(mktemp)
  cat <<-EOF > ${dockerconfigjson_file}
  {
    "auths": {
      "eu.gcr.io": {
        "username": "_json_key",
        "email": "auth@jetstack.io",
        "auth": "$(echo "_json_key:$(cat ${pullsecret_file})" | base64 -${BASE64_WRAP_SWITCH} 0)"
      }
    }
  }
EOF
cat ${dockerconfigjson_file} && rm ${dockerconfigjson_file} && rm ${pullsecret_file}
}

deploy-tlspk-agent() {
  tlspk_agent_yaml_file=$(stash-tlspk-agent-yaml)
  logger "deploying TLSPK agent"

  local json_creds='{"user_id": "'"${TLSPK_SA_USER_ID}"'","user_secret": "'"$(echo ${TLSPK_SA_USER_SECRET} | sed 's/"/\\"/g')"'"}'
  local json_creds_b64=$(echo ${json_creds} | base64 -${BASE64_WRAP_SWITCH} 0)
  curl -sL https://raw.githubusercontent.com/jetstack/jsctl/main/internal/cluster/templates/agent.yaml | \
    sed "s/{{ .Organization }}/${TLSPK_ORG}/g" | \
    sed "s/{{ .Name }}/$(tr "-" "_" <<< ${TLSPK_CLUSTER_NAME})/g" | \
    sed "s/{{ .CredentialsJSON }}/$(echo ${json_creds_b64} | sed 's/\//\\\//g')/g" | \
    kubectl apply -f -
  
  logger "deploying TLSPK agent: awaiting steady state"
  sleep 5 && kubectl -n jetstack-secure wait --for=condition=Available=True --all deployments --timeout=-1s
}

install-operator() {
  logger "creating/fetching eu.gcr.io private image pull secret"

  logger "replicating secret into cluster"
  kubectl -n jetstack-secure delete secret jse-gcr-creds >/dev/null 2>&1 || true
  kubectl -n jetstack-secure create secret docker-registry jse-gcr-creds \
    --from-file .dockerconfigjson=<(get-dockerconfig)

  logger "installing the operator"
  helm -n jetstack-secure upgrade -i js-operator \
    oci://eu.gcr.io/jetstack-secure-enterprise/charts/js-operator   \
    --version v0.0.1-alpha.24 \
    --registry-config <(get-dockerconfig) \
    --set images.secret.enabled=true   \
    --set images.secret.name=jse-gcr-creds \
    --wait

  logger "installing the operator: awaiting steady state"
  sleep 5 && kubectl -n jetstack-secure wait --for=condition=Available=True --all deployments --timeout=-1s
}

deploy-operator-components() {
  logger "deploy operator components"

  kubectl create -f - <<EOF
  apiVersion: operator.jetstack.io/v1alpha1
  kind: Installation
  metadata:
    name: jetstack-secure
  spec:
    approverPolicy: {}
    certManager:
      controller:
        replicas: 1
      webhook:
        replicas: 1
    images:
      secret: jse-gcr-creds
EOF

  logger "deploy operator components: awaiting steady state"
  sleep 5 && kubectl -n jetstack-secure wait --for=condition=Available=True --all deployments --timeout=-1s
  kubectl -n jetstack-secure wait pod -l app=cert-manager --for=condition=Ready --timeout=-1s
  kubectl -n jetstack-secure wait pod -l app=webhook --for=condition=Ready --timeout=-1s
}

deploy-self-signed-issuer() {
  logger "deploying a self-signed issuer"
  patchfile=$(mktemp)
  cat <<EOF > ${patchfile}
  spec:
    issuers:
      - name: self-signed
        clusterScope: true
        selfSigned: {}
EOF
  kubectl patch installation jetstack-secure --type merge --patch-file ${patchfile}
  rm ${patchfile}

  logger "deploy operator components: awaiting steady state"
  sleep 5 # not sure we can "wait" on anything so just give the issuer a moment to appear
}

create-demo-certs() {
  logger "create demo certs"

  vars=("hydrogen" "helium" "lithium" "beryllium" "boron" "carbon" "nitrogen" "oxygen" "fluorine" "neon")
  for var in "${vars[@]}"; do
    if [[ -z "${!var}" ]]; then
    cat << EOF | kubectl apply -f -
    apiVersion: cert-manager.io/v1
    kind: Certificate
    metadata:
      name: ${var}.elements.com
    spec:
      secretName: ${var}-elements-com-tls
      dnsNames:
        - ${var}.elements.com
      issuerRef:
        name: self-signed
        kind: ClusterIssuer
        group: cert-manager.io
EOF
    fi
  done
}

help () {
  echo "Accepted exported or inlined environment variables are:"
  echo -e "\tCOMMAND              ->> one of the following: get-oauth-token"
  echo -e "\t                                               get-dockerconfig"
  echo -e "\t                                               deploy-tlspk-agent"
  echo -e "\t                                               install-operator"
  echo -e "\t                                               deploy-operator-components"
  echo -e "\t                                               deploy-self-signed-issuer"
  echo -e "\t                                               create-demo-certs"
  echo -e "\tTLSPK_SA_USER_ID     ->> The User ID of a TLSPK service account"
  echo -e "\tTLSPK_SA_USER_SECRET ->> The User Secret of a TLSPK service account"
  echo -e "\t[TLSPK_CLUSTER_NAME] ->> The name of the cluster you wish to create/report"
}

# main
trap "finally" EXIT
set -e

if [ "${DEBUG}" == "true" ]; then
  set -x
fi

check-vars "TLSPK_SA_USER_ID" "TLSPK_SA_USER_SECRET"
check-dependency curl
derive-org-from-user
case ${COMMAND} in
  'help')
    help
    exit 0
    ;;
  'get-oauth-token')
    get-oauth-token
    exit 0
    ;;
  'get-dockerconfig')
    check-dependency jq
    get-dockerconfig
    exit 0
    ;;
  'deploy-tlspk-agent')
    check-dependency kubectl
    deploy-tlspk-agent
    exit 0
    ;;
  'install-operator')
    check-dependency kubectl
    install-operator
    exit 0
    ;;
  'deploy-operator-components')
    check-dependency kubectl
    deploy-operator-components
    exit 0
    ;;
  'deploy-self-signed-issuer')
    check-dependency kubectl
    deploy-self-signed-issuer
    exit 0
    ;;
  'create-demo-certs')
    check-dependency kubectl
    create-demo-certs
    exit 0
    ;;
  *)
    echo "unknown COMMAND ${COMMAND}"
    help
    exit 1
    ;;
esac
