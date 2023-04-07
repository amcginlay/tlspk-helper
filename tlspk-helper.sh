#!/usr/bin/env bash

# TODO
# - '--auto-approve' on its own should fail
# - make certificate generation a little more interesting

SCRIPT_NAME="tlspk-helper.sh"
SCRIPT_VERSION="0.1"
OPERATOR_VERSION_DEFAULT="v0.0.1-alpha.24"
BASE64_WRAP_SWITCH=$(uname | grep -q Darwin && echo b || echo w)

: ${DEBUG:="false"}

function logger() {
  true # echo "${SCRIPT_NAME}: $1"
}

finally() {
  local result=$?
  if [ "$result" != "0" ]; then
    echo "aborting!"
  fi
  exit $result
}

check-vars() {
  local result=
  for var in "$@"; do
    if [[ -z "${!var}" ]]; then
      echo "$var is not set"
      result=1
    fi
  done
  return ${result}
}

check-dependencies() {
  while [[ $# -gt 0 ]]; do
    command -v ${1} >/dev/null 2>&1 || {
      echo "missing dependency: ${1}"
      return 1
    }
    shift
  done
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
  TLSPK_ORG=$(cut -d'@' -f2- <<< ${TLSPK_SA_USER_ID} | cut -d'.' -f1)
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
    --data "${pull_secret_request}")
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
    mkdir -p $(get-config-dir)
    create-secret > ${secret_filename}
  fi
  cat ${secret_filename}
}

extract-secret-data() {
  local result=
  if ! result=$(get-secret); then echo ${result}; return 126; fi
  jq '.[0].key.privateData' --raw-output <<< ${result} | base64 --decode
}

get-dockerconfig()
{
  check-dependencies jq # via extract-secret-data
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

show-cluster-status() {
  echo "Current context is $(kubectl config current-context)"
  kubectl cluster-info | head -2
}

approve-destructive-operation() {
  show-cluster-status
  if [ -z ${APPROVED+x} ]; then
    read -p "Are you sure you want to approved this action? [y/N]" APPROVED
  fi
  if grep -qv "^y\|Y" <<< ${APPROVED}; then
    echo "Potentially destructive operation not approved. Override with '--auto-approve'"
    return 1
  fi
}

discover-tls-secrets() {
  check-dependencies jq kubectl
  show-cluster-status
  kubectl get --raw /api/v1/secrets | jq -r '.items[] | select(.type == "kubernetes.io/tls") | "/namespaces/\(.metadata.namespace)/secrets/\(.metadata.name)"'
}

check-undeployed() {
  check-dependencies kubectl
  if kubectl get namespace ${1} >/dev/null 2>&1; then
    if kubectl -n ${1} rollout status deployment ${2} >/dev/null 2>&1; then
      echo "${1}/${2} is already deployed"
      return 1
    fi
  fi
  # if we got here, ${1}/${2} can be deployed
}

check-deployed() {
  check-dependencies kubectl
  if kubectl get namespace ${1} >/dev/null 2>&1; then
    if kubectl -n ${1} rollout status deployment ${2} >/dev/null 2>&1; then
      return 0
    fi
  fi
  echo "${1}/${2} is not deployed"
  return 1
}

deploy-agent() {
  check-dependencies kubectl
  check-undeployed jetstack-secure agent
  approve-destructive-operation

  logger "deploying TLSPK agent"

  local json_creds='{"user_id": "'"${TLSPK_SA_USER_ID}"'","user_secret": "'"$(echo ${TLSPK_SA_USER_SECRET} | sed 's/"/\\"/g')"'"}'
  local json_creds_b64=$(echo ${json_creds} | base64 -${BASE64_WRAP_SWITCH} 0)
  local tlkps_cluster_name_adj=$(tr "-" "_" <<< ${TLSPK_CLUSTER_NAME})
  curl -sL https://raw.githubusercontent.com/jetstack/jsctl/main/internal/cluster/templates/agent.yaml | \
    sed "s/{{ .Organization }}/${TLSPK_ORG}/g" | \
    sed "s/{{ .Name }}/${tlkps_cluster_name_adj}/g" | \
    sed "s/{{ .CredentialsJSON }}/$(echo ${json_creds_b64} | sed 's/\//\\\//g')/g" | \
    kubectl apply -f -
  
  logger "deploying TLSPK agent: awaiting steady state"
  sleep 5 && kubectl -n jetstack-secure wait --for=condition=Available=True --all deployments --timeout=-1s
  echo "Cluster will appear in TLSPK as ${tlkps_cluster_name_adj}"
}

install-operator() {
  check-dependencies kubectl
  check-undeployed jetstack-secure js-operator-operator
  approve-destructive-operation

  logger "replicating secret into cluster"
  kubectl create namespace jetstack-secure >/dev/null 2>&1 || true
  kubectl -n jetstack-secure delete secret jse-gcr-creds >/dev/null 2>&1 || true
  kubectl -n jetstack-secure create secret docker-registry jse-gcr-creds --from-file .dockerconfigjson=<(get-dockerconfig)

  logger "installing the operator"
  helm -n jetstack-secure upgrade -i js-operator \
    oci://eu.gcr.io/jetstack-secure-enterprise/charts/js-operator   \
    --version ${OPERATOR_VERSION} \
    --registry-config <(get-dockerconfig) \
    --set images.secret.enabled=true   \
    --set images.secret.name=jse-gcr-creds \
    --wait

  logger "installing the operator: awaiting steady state"
  sleep 5 && kubectl -n jetstack-secure wait --for=condition=Available=True --all deployments --timeout=-1s
}

deploy-operator-components() {
  check-dependencies kubectl
  check-undeployed jetstack-secure cert-manager
  approve-destructive-operation

  logger "deploy operator components (inc. cert-manager)"

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

create-self-signed-issuer() {
  check-dependencies kubectl
  check-deployed jetstack-secure cert-manager
  approve-destructive-operation

  logger "creating a self-signed issuer"
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
  check-dependencies kubectl
  check-deployed jetstack-secure cert-manager
  approve-destructive-operation

  logger "create demo certs"

  kubectl create namespace demo-certs
  local vars=("hydrogen" "helium" "lithium" "beryllium" "boron" "carbon" "nitrogen" "oxygen" "fluorine" "neon")
  for var in "${vars[@]}"; do
    if [[ -z "${!var}" ]]; then
    cat << EOF | kubectl -n demo-certs apply -f -
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

usage() {
  echo "Helper script for TLS Protect for Kubernetes (v${SCRIPT_VERSION})"
  echo
  echo "Usage:"
  echo "  ./${SCRIPT_NAME} [command]"
  echo
  echo "Available Commands:"
  echo "  get-oauth-token            Obtains token for TLSPK_SA_USER_ID/TLSPK_SA_USER_SECRET pair"
  echo "  get-dockerconfig           Obtains Docker-compatible registry config / image pull secret (as used with 'helm upgrade --registry-config')"
  echo "  discover-tls-secrets       Scan the current cluster for TLS secrets (i.e. certificates)"
  echo "  deploy-agent               Deploys the TLSPK agent component"
  echo "  install-operator           Installs the TLSPK operator"
  echo "  deploy-operator-components Deploys minimal operator components, incluing cert-manager"
  echo "  create-self-signed-issuer  Use cert-manager ClusterIssuer CRD to define a cluster-wide self-signed issuer"
  echo "  create-demo-certs          Use cert-manager Certificate CRD to define a collection of self-signed certificates in the demo-certs namespace"
  echo
  echo "Flags:"
  echo "  --auto-approve             Suppress prompts regarding potentially destructive operations"
  echo "  --operator-version <value> The version of the operator to install (default is ${OPERATOR_VERSION_DEFAULT})"
  echo "  --cluster-name <value>     The cluster name to be registered in TLSPK (default is autogenerated or derived from 'kubectl config current-context')"
  echo
  echo "Environment Variables:"
  echo "  TLSPK_SA_USER_ID           User ID of a TLSPK service account (required)"
  echo "  TLSPK_SA_USER_SECRET       User Secret of a TLSPK service account (required - use single-quotes to preserve control chars!)"
}

# ----- MAIN -----
trap "finally" EXIT
set -e

if [ "${DEBUG}" == "true" ]; then
  set -x
fi

check-vars "TLSPK_SA_USER_ID" "TLSPK_SA_USER_SECRET"
check-dependencies curl
derive-org-from-user

if [[ $# -eq 0 ]]; then set "usage"; fi # fake arg if none
INPUT_ARGUMENTS="${@}"
set -u
unset COMMAND APPROVED
while [[ $# -gt 0 ]]; do
  case $1 in
    'usage'|'get-oauth-token'|'get-dockerconfig'|'discover-tls-secrets'|'deploy-agent'|'install-operator'|'deploy-operator-components'|'create-self-signed-issuer'|'create-demo-certs')
      COMMAND=$1
      ;;
    '--auto-approve')
      APPROVED="y"
      ;;
    '--operator-version')
      shift
      OPERATOR_VERSION="${1}"
      ;;
    '--cluster-name')
      shift
      TLSPK_CLUSTER_NAME="${1}"
      ;;
    *) 
      echo "Unrecognised command ${INPUT_ARGUMENTS}"
      usage
      exit 1
      ;;
  esac
  shift
done
set +u

: ${OPERATOR_VERSION:=${OPERATOR_VERSION_DEFAULT}}

if kubectl config current-context >/dev/null &2>1; then
  : ${TLSPK_CLUSTER_NAME:=$(kubectl config current-context | cut -c-23)-$(date +"%y%m%d%H%M")}
else  
  : ${TLSPK_CLUSTER_NAME:=k8s-$(date +"%y%m%d%H%M")}
fi

${COMMAND}
