#!/usr/bin/env bash

# TODO
# work out why constructs like result=$(extract-secret-data) in get-dockerconfig cause base64 to blow up (definitely a quotes thing, but tempfiles seem to work OK for now).
# work on eliminating the ugly "side effect" in get-dockerconfig

SCRIPT_NAME="tlspk-helper.sh"
SCRIPT_VERSION="0.1"
OPERATOR_VERSION_DEFAULT="v0.0.1-alpha.24"
BASE64_WRAP_SWITCH=$(uname | grep -q Darwin && echo b || echo w)
OPENSSL_NEGATIVE_DAYS=$(uname | grep -q Darwin && echo || echo -) # MacOS openssl doesn't support -ve days (for simulating expired certs)

: ${DEBUG:="false"}

logger() {
  echo "${SCRIPT_NAME}: $1"
}

finally() {
  exit_code=$?
  if [ "$exit_code" != "0" ]; then
    echo "aborting!"
  fi
  rm -rf ${temp_dir}
  exit $exit_code
}

check-vars() {
  exit_code=0
  for var in "$@"; do
    if [[ -z "${!var}" ]]; then
      echo "$var is not set (use export)"
      exit_code=1
    fi
  done
  return ${exit_code}
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
  http_code=$(curl --no-progress-meter -L -w "%{http_code}" -o ${temp_dir}/token.out https://auth.jetstack.io/oauth/token \
    --data "audience=https://preflight.jetstack.io/api/v1" \
    --data "client_id=jmQwDGl86WAevq6K6zZo6hJ4WUvp14yD" \
    --data "grant_type=password" \
    --data "username=${TLSPK_SA_USER_ID}" \
    --data-urlencode "password=${TLSPK_SA_USER_SECRET}")
  cat ${temp_dir}/token.out
  if grep -qv "^2" <<< ${http_code}; then return 1; fi
}

check-auth() {
  if ! get-oauth-token >/dev/null 2>&1; then
    logger "TLSPK_SA_USER_ID and/or TLSPK_SA_USER_SECRET creds do not yield an OAuth token. Check and correct before retrying."
    return 1
  fi
}

derive-org-from-user() {
  TLSPK_ORG=$(cut -d'@' -f2- <<< ${TLSPK_SA_USER_ID} | cut -d'.' -f1)
}

get-secret-name() {
  echo "ips-$(hostname)-${TLSPK_SA_USER_ID}"
}

create-secret() {
  set +e
  if ! oauth_token_json=$(get-oauth-token); then echo ${oauth_token_json}; return 1; fi
  set -e
    
  oauth_token=$(jq .access_token --raw-output <<< ${oauth_token_json})
  pull_secret_request='[{"id":"","displayName":"'"$(get-secret-name)"'"}]'
  http_code=$(curl --no-progress-meter -L -w "%{http_code}" -o ${temp_dir}/svc_account.out -X POST https://platform.jetstack.io/subscription/api/v1/org/${TLSPK_ORG}/svc_accounts \
    --header "authorization: Bearer ${oauth_token}" \
    --data "${pull_secret_request}")
  cat ${temp_dir}/svc_account.out
  if grep -qv "^2" <<< ${http_code}; then return 127; fi
}

get-config-dir() {
  echo "${HOME}/.tlspk/"
}

get-secret-filename() {
  echo $(get-config-dir)$(get-secret-name).json
}

get-secret() {
  secret_filename=$(get-secret-filename)
  if ! [ -f ${secret_filename} ]; then
    mkdir -p $(get-config-dir)
    set +e
    if ! secret=$(create-secret); then echo ${secret}; return 1; fi
    echo ${secret} > ${secret_filename}
  fi
  cat ${secret_filename}
}

extract-secret-data() {
  if ! secret=$(get-secret); then echo ${secret}; return 1; fi
  jq '.[0].key.privateData' --raw-output <<< ${secret} | base64 --decode -${BASE64_WRAP_SWITCH} 0
}

get-dockerconfig()
{
  set +e
  if ! extract-secret-data > ${temp_dir}/pull_secret.out; then echo ${secret}; return 1; fi # NOTE secret set in extract-secret-data (side effect)
  set -e

  # despite documentation to the contrary, I don't believe "auths:eu.gcr.io:password" is required, so it's omitted
  cat <<-EOF > ${temp_dir}/dockerconfig_json.out
  {
    "auths": {
      "eu.gcr.io": {
        "username": "_json_key",
        "email": "auth@jetstack.io",
        "auth": "$(echo "_json_key:$(cat  ${temp_dir}/pull_secret.out)" | base64 -${BASE64_WRAP_SWITCH} 0)"
      }
    }
  }
EOF
cat ${temp_dir}/dockerconfig_json.out
}

show-cluster-status() {
  logger "Current context is $(kubectl config current-context)"
  kubectl cluster-info | head -2
}

approve-destructive-operation() {
  if [ -z ${APPROVED+x} ]; then
    read -p "Are you sure? [y/N] " APPROVED
  fi
  if grep -qv "^y\|Y" <<< ${APPROVED}; then
    logger "potentially destructive operation not approved. Override with '--auto-approve'"
    return 1
  fi
}

create-unsafe-tls-secrets() {
  cat <<EOF > ${temp_dir}/ssl.conf
  [ req ]
  default_bits		= 2048
  distinguished_name	= req_distinguished_name
  req_extensions		= req_ext
  
  [ req_distinguished_name ]
  commonName          = kryptonite.elements.com
  
  [ req_ext ]
  keyUsage            = digitalSignature, keyEncipherment
  extendedKeyUsage    = serverAuth
  subjectAltName      = @alt_names
  
  [ alt_names ]
  DNS.1               = kryptonite.elements.com
EOF
  openssl genrsa -out ${temp_dir}/key.pem 2048 # https://gist.github.com/croxton/ebfb5f3ac143cd86542788f972434c96
  openssl req -new -key ${temp_dir}/key.pem -out ${temp_dir}/csr.pem -subj "/CN=kryptonite.elements.com" -reqexts req_ext -config ${temp_dir}/ssl.conf
  openssl x509 -req -in ${temp_dir}/csr.pem -signkey ${temp_dir}/key.pem -out ${temp_dir}/cert.pem -days ${OPENSSL_NEGATIVE_DAYS}1 -extensions req_ext -extfile ${temp_dir}/ssl.conf
  kubectl create namespace demo-certs 2>/dev/null || true
  kubectl -n demo-certs create secret tls kryptonite-elements-com-tls --cert=${temp_dir}/cert.pem --key=${temp_dir}/key.pem
}

discover-tls-secrets() {
  show-cluster-status
  logger "The following certificates were discovered:"
  kubectl get --raw /api/v1/secrets | jq -r '.items[] | select(.type == "kubernetes.io/tls") | "/namespaces/\(.metadata.namespace)/secrets/\(.metadata.name)"'
}

check-undeployed() {
  if kubectl get namespace ${1} >/dev/null 2>&1; then
    if kubectl -n ${1} rollout status deployment ${2} >/dev/null 2>&1; then
      echo "${1}/${2} is already deployed"
      return 1
    fi
  fi
  # if we got here, ${1}/${2} can be deployed
}

check-deployed() {
  if kubectl get namespace ${1} >/dev/null 2>&1; then
    if kubectl -n ${1} rollout status deployment ${2} >/dev/null 2>&1; then
      return 0
    fi
  fi
  echo "${1}/${2} is not deployed"
  return 1
}

deploy-agent() {
  check-undeployed jetstack-secure agent
  check-auth
  show-cluster-status
  approve-destructive-operation

  logger "deploying TLSPK agent"

  json_creds='{"user_id": "'"${TLSPK_SA_USER_ID}"'","user_secret": "'"$(echo ${TLSPK_SA_USER_SECRET} | sed 's/"/\\"/g')"'"}'
  json_creds_b64=$(echo ${json_creds} | base64 -${BASE64_WRAP_SWITCH} 0)
  tlkps_cluster_name_adj=$(tr "-" "_" <<< ${TLSPK_CLUSTER_NAME})
  curl -sL https://raw.githubusercontent.com/jetstack/jsctl/main/internal/cluster/templates/agent.yaml | \
    sed "s/{{ .Organization }}/${TLSPK_ORG}/g" | \
    sed "s/{{ .Name }}/${tlkps_cluster_name_adj}/g" | \
    sed "s/{{ .CredentialsJSON }}/$(echo ${json_creds_b64} | sed 's/\//\\\//g')/g" | \
    kubectl apply -f -
  
  logger "deploying TLSPK agent: awaiting steady state"
  sleep 5 && kubectl -n jetstack-secure wait --for=condition=Available=True --all deployments --timeout=-1s
  logger "cluster will appear in TLSPK as ${tlkps_cluster_name_adj}"
}

install-operator() {
  check-undeployed jetstack-secure js-operator-operator
  show-cluster-status
  approve-destructive-operation

  logger "replicating secret into cluster"
  kubectl create namespace jetstack-secure 2>/dev/null || true
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
  check-undeployed jetstack-secure cert-manager
  show-cluster-status
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
  check-deployed jetstack-secure cert-manager
  show-cluster-status
  approve-destructive-operation

  logger "creating a self-signed issuer"
  cat <<EOF > ${temp_dir}/patchfile
  spec:
    issuers:
      - name: self-signed
        clusterScope: true
        selfSigned: {}
EOF
  kubectl patch installation jetstack-secure --type merge --patch-file ${temp_dir}/patchfile

  logger "deploy operator components: awaiting steady state"
  sleep 5 # not sure we can "wait" on anything so just give the issuer a moment to appear
}

create-safe-tls-secrets() {
  check-deployed jetstack-secure cert-manager
  show-cluster-status
  approve-destructive-operation

  logger "create cert-manager certs"

  kubectl create namespace demo-certs 2>/dev/null || true
  subdomains=("hydrogen" "helium" "lithium" "beryllium" "boron" "carbon" "nitrogen" "oxygen" "fluorine" "neon")
  durations=( "8760"     "4320"   "2160"    "720"       "240"   "120"    "96"       "24"     "6"        "1")
  for i in "${!subdomains[@]}"; do
    cat << EOF | kubectl -n demo-certs apply -f -
    apiVersion: cert-manager.io/v1
    kind: Certificate
    metadata:
      name: ${subdomains[i]}.elements.com
    spec:
      secretName: ${subdomains[i]}-elements-com-tls
      dnsNames:
        - ${subdomains[i]}.elements.com
      duration: ${durations[i]}h
      usages:
      - digital signature
      - key encipherment
      - server auth
      issuerRef:
        name: self-signed
        kind: ClusterIssuer
        group: cert-manager.io
EOF
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
  echo "  create-unsafe-tls-secrets  Define TLS Secrets in the demo-certs namespace (NOT protected by cert-manager)"
  echo "  discover-tls-secrets       Scan the current cluster for TLS secrets"
  echo "  deploy-agent               Deploys the TLSPK agent component"
  echo "  install-operator           Installs the TLSPK operator"
  echo "  deploy-operator-components Deploys minimal operator components, incluing cert-manager"
  echo "  create-self-signed-issuer  Use cert-manager ClusterIssuer CRD to define a cluster-wide self-signed issuer"
  echo "  create-safe-tls-secrets    Use cert-manager Certificate CRD to define a collection of self-signed certificates in the demo-certs namespace"
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

temp_dir=$(mktemp -d)
check-vars "TLSPK_SA_USER_ID" "TLSPK_SA_USER_SECRET"
check-dependencies jq git kubectl
derive-org-from-user

if [[ $# -eq 0 ]]; then set "usage"; fi # fake arg if none
INPUT_ARGUMENTS="${@}"
set -u
unset COMMAND APPROVED
while [[ $# -gt 0 ]]; do
  case $1 in
    'usage'|'get-oauth-token'|'get-dockerconfig'|'create-unsafe-tls-secrets'|'discover-tls-secrets'|'deploy-agent'|'install-operator'|'deploy-operator-components'|'create-self-signed-issuer'|'create-safe-tls-secrets'|'check-auth'|'extract-secret-data'|'get-secret'|'get-secret-filename'|'get-config-dir'|'create-secret')
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

if kubectl config current-context >/dev/null 2>&1; then
  : ${TLSPK_CLUSTER_NAME:=$(kubectl config current-context | tr '@' '.' | cut -c-21)-$(date +"%y%m%d%H%M")}
else  
  : ${TLSPK_CLUSTER_NAME:=k8s-$(date +"%y%m%d%H%M")}
fi

${COMMAND}
