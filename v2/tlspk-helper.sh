#!/usr/bin/env bash

SCRIPT_NAME="tlspk-helper.sh"
SCRIPT_VERSION="2.0"
AGENT_VERSION_DEFAULT="0.2.1"               # (legacy) gcrane ls eu.gcr.io/jetstack-secure-enterprise/charts/jetstack-agent
OPERATOR_VERSION_DEFAULT="v0.0.1-alpha.26"  # (legacy) gcrane ls eu.gcr.io/jetstack-secure-enterprise/charts/js-operator

KUBECTL_VERSION_DEFAULT="1.27.7/2023-11-14"
K3D_IMAGE_VERSION_DEFAULT="v1.27.4-k3s1"    # from https://hub.docker.com/r/rancher/k3s/tags
VENCTL_VERSION_DEFAULT="1.3.0"              # from https://gitlab.com/venafi/vaas/applications/tls-protect-for-k8s/venctl/-/releases
CERT_MANAGER_VERSION_DEFAULT="v1.13.3"
VEI_VERSION_DEFAULT="v0.11.0"
OWNING_TEAM=k8s-cluster-discovery-demo-team

MISSING_ENV_VAR_MSG="The following REQUIRED environment variables are missing:"
MISSING_PACKAGE_DEPENDENCIES_MSG="The following REQUIRED package dependencies are missing:"
BASE64_WRAP_SWITCH=$(uname | grep -q Darwin && echo b || echo w)

: ${DEBUG:="false"}

log-info() {
  echo "${SCRIPT_NAME} [info]: $1"
}

log-error() {
  echo "${SCRIPT_NAME} [error]: $1" >&2
  return 1
}

finally() {
  local exit_code=$?
  if [[ "$exit_code" != "0" ]]; then
    log-info "Aborting!"
  fi
  rm -rf ${temp_dir}
  exit $exit_code
}

check-vars() {
  local required_vars=("TLSPK_SA_USER_ID" "TLSPK_SA_USER_SECRET" "VCP_REGION" "VCP_APIKEY")
  local missing_vars=()
  set +u # <<< allow test for potentially unbound variable
  for var in "${required_vars[@]}"; do
    if [[ -z "${!var}" ]]; then
      missing_vars+=("${var}")
    fi
  done
  set -u # <<< revert
  if [[ ${#missing_vars[@]} -ne 0 ]]; then
    log-error "${MISSING_ENV_VAR_MSG} ${missing_vars[*]}"
    return 1
  fi
}

get-os() {
  local uname_result=$(uname -a)
  grep -q "amzn" <<< ${uname_result}   && echo "amzn" && return
  grep -q "Ubuntu" <<< ${uname_result} && echo "ubuntu" && return
  grep -q "Darwin" <<< ${uname_result} && echo "darwin" && return
  log-error "Unsupported OS: uname=${uname_result}"
  return 1
}

get-package-manager() {
  local os=$(get-os)
  [[ "${os}" == "amzn" ]]   && echo "yum" && return
  [[ "${os}" == "ubuntu" ]] && echo "apt" && return
  log-error "No package manager support for ${os}"
  return 1
}

get-regional-url() {
  grep -q "US" <<< ${VCP_REGION} && echo "api.venafi.cloud" && return
  grep -q "EU" <<< ${VCP_REGION} && echo "api.venafi.eu" && return
  log-error "Unsupported Region: VCP_REGION=${VCP_REGION}. Supported regions are US and EU" 
}

get-missing-package-dependencies() {
  local required=("$@")
  local missing=()
  for package in "${required[@]}"; do
    if ! command -v "$package" &> /dev/null; then
      missing+=("$package")
    fi
  done
  if [[ ${#missing[@]} -ne 0 ]]; then echo ${missing[*]}; fi
}

install-dependencies() {
  local missing_packages=($(get-missing-package-dependencies "jq" "git" "gpg-agent" "kubectl" "helm" "docker" "k3d" "venctl"))
  if [[ ${#missing_packages[@]} -gt 0 ]]; then
    log-info "${MISSING_PACKAGE_DEPENDENCIES_MSG} ${missing_packages[*]}"
    local os=$(get-os)
    if [[ "${os}" != "amzn" && "${os}" != "ubuntu" ]]; then
      log-error "Manual installation of these package dependencies is required for your OS"
      return 1
    fi
    log-info "This operation will install the missing package dependencies"
    approve-destructive-operation
    local pm=$(get-package-manager)
    for package in "${missing_packages[@]}"; do
      case ${package} in
        jq | git )
          sudo ${pm} update -y
          sudo ${pm} install ${package} -y
          ;;
        gpg-agent )
          sudo ${pm} update -y
          sudo ${pm} install gnupg2 -y --allowerasing # includes gpg-agent
          ;;
        kubectl )
          curl -O -s https://s3.us-west-2.amazonaws.com/amazon-eks/${KUBECTL_VERSION}/bin/$(uname | tr '[:upper:]' '[:lower:]')/amd64/kubectl
          chmod +x ./kubectl
          sudo mv ./kubectl /usr/bin/
          cat > ${HOME}/.kubectl-ac << EOF
          source <(kubectl completion bash)
          alias kc=kubectl
          complete -F __start_kubectl kc
EOF
          echo "source ${HOME}/.kubectl-ac" >> ${HOME}/.bashrc # shell restart required
          ;;
        helm )
          curl -fsSL -o ${temp_dir}/get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
          chmod 700 ${temp_dir}/get_helm.sh
          HELM_INSTALL_DIR=/usr/bin ${temp_dir}/get_helm.sh
          ;;
        docker )
          sudo ${pm} update -y
          if [[ "${os}" == "amzn" ]]; then
            sudo ${pm} install -y docker
          else # ubuntu
            sudo ${pm} install -y apt-transport-https ca-certificates curl software-properties-common
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
            sudo ${pm} update -y # for new sources
            apt-cache policy docker-ce
            sudo ${pm} install -y docker-ce
          fi
          sudo usermod -a -G docker ${USER}
          newgrp docker << EOF
          sudo systemctl enable docker.service
          sudo systemctl start docker.service
EOF
          ;;
        k3d )
          curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | K3D_INSTALL_DIR=/usr/bin bash
          ;;
        venctl )
          curl -sSfL https://dl.venafi.cloud/venctl/latest/installer.sh | VERSION=${VENCTL_VERSION} sudo sh
          ;;
        * ) 
          log-error "Unrecognised package dependency: ${package}"
          return 1
          ;;
      esac
    done
    log-info "Required package dependencies successfully installed"
    if printf '%s\n' "${missing_packages[@]}" | grep -q "^docker$\|^kubectl$"; then
      log-info "!!!! IMPORTANT: please restart shell session OR issue command 'newgrp docker' for all changes to become effective !!!!"
    fi
  fi
}

create-local-k8s-cluster() {
  local missing_packages=($(get-missing-package-dependencies "docker" "k3d" "kubectl"))
  if [[ ${#missing_packages[@]} -gt 0 ]]; then
    log-error "${MISSING_PACKAGE_DEPENDENCIES_MSG} ${missing_packages[*]}"
    return 1
  fi
  local os=$(get-os)
  case ${os} in
    amzn | ubuntu )
      log-info "Creating a new Kubernetes cluster using k3d on localhost"
      newgrp docker << EOF
        if sudo lsof -i :80 > /dev/null 2>&1 || sudo lsof -i :443 > /dev/null 2>&1; then 
          k3d cluster create ${TLSPK_CLUSTER_NAME} --image k3s:${K3D_IMAGE_VERSION}  --wait # 80/443 TAKEN, NO LOADBALANCER
        else
          k3d cluster create ${TLSPK_CLUSTER_NAME} --image k3s:${K3D_IMAGE_VERSION}  --wait -p 80:80@loadbalancer -p 443:443@loadbalancer
        fi
        k3d kubeconfig merge ${TLSPK_CLUSTER_NAME} --kubeconfig-merge-default --kubeconfig-switch-context
EOF
      ;;
    darwin )
      log-info "Creating a new Kubernetes cluster using k3d on localhost"
      k3d cluster create ${TLSPK_CLUSTER_NAME} --wait # simple install, avoid sudo
      ;;
    * )
      log-error "Unrecognised OS: ${os}"
      return 1
      ;;
  esac
  
  log-info "Awaiting cluster steady state (ignore any memcache/metrics errors here)"
  sleep 5 && kubectl -n kube-system wait --for=condition=Available=True --all deployments --timeout=300s
  kubectl -n kube-system wait pod -l k8s-app=metrics-server --for=condition=Ready --timeout=300s

  show-cluster-status
}

get-oauth-token() {
  local method_type=POST
  local url=https://auth.jetstack.io/oauth/token
  local http_code=$(curl --no-progress-meter -L -w "%{http_code}" -o ${temp_dir}/token.out \
    -X ${method_type} ${url} \
    --data "audience=https://preflight.jetstack.io/api/v1" \
    --data "client_id=jmQwDGl86WAevq6K6zZo6hJ4WUvp14yD" \
    --data "grant_type=password" \
    --data "username=${TLSPK_SA_USER_ID}" \
    --data-urlencode "password=${TLSPK_SA_USER_SECRET}")
  if grep -qv "^2" <<< ${http_code}; then 
    log-error "${method_type} ${url} failed: status code=${http_code} response='$(cat ${temp_dir}/token.out)'"
    return 1
  fi
  cat ${temp_dir}/token.out
}

derive-org-from-user() {
  TLSPK_ORG=$(cut -d'@' -f2- <<< ${TLSPK_SA_USER_ID} | cut -d'.' -f1) # TLSPK_ORG is globally scoped
}

unpatch-user-secret() {
  # HACK! never found a proper fix for preserving '$' from CloudFormation preprocessing
  # use sed 's/\$/_DOLLAR_/g' in the UserData to allow exported vars to pass thru
  # this function is the counterpart which reverses that hack
  TLSPK_SA_USER_SECRET=$(sed 's/_DOLLAR_/\$/g' <<< ${TLSPK_SA_USER_SECRET}) # TLSPK_SA_USER_SECRET is globally scoped
}

get-secret-name() {
  echo "ips-$(hostname)-${TLSPK_SA_USER_ID}"
}

create-secret() {
  if ! oauth_token_json=$(get-oauth-token); then 
    log-error "get-oauth-token failed"
    return 1
   fi
  local oauth_token=$(jq .access_token --raw-output <<< ${oauth_token_json})
  local pull_secret_request='[{"id":"","displayName":"'"$(get-secret-name)"'"}]'
  local method_type=POST
  local url=https://platform.jetstack.io/subscription/api/v1/org/${TLSPK_ORG}/svc_accounts
  local http_code=$(curl --no-progress-meter -L -w "%{http_code}" -o ${temp_dir}/svc_account.out \
    -X ${method_type} ${url} \
    --header "authorization: Bearer ${oauth_token}" \
    --data "${pull_secret_request}")
  if grep -qv "^2" <<< ${http_code}; then
    log-error "${method_type} ${url} failed: status code=${http_code} response='$(cat ${temp_dir}/svc_account.out)'"
    return 1
  fi
  cat ${temp_dir}/svc_account.out
}

get-config-dir() {
  echo "${HOME}/.tlspk/"
}

get-secret-filename() {
  echo $(get-config-dir)$(get-secret-name).json
}

get-secret() {
  local secret_filename=$(get-secret-filename)
  if ! [[ -f ${secret_filename} ]]; then
    mkdir -p $(get-config-dir)
    if ! secret=$(create-secret); then
      return 1
    fi
    echo ${secret} > ${secret_filename}
  fi
  cat ${secret_filename}
}

extract-secret-data() {
  local missing_packages=($(get-missing-package-dependencies "jq"))
  if [[ ${#missing_packages[@]} -gt 0 ]]; then
    log-error "${MISSING_PACKAGE_DEPENDENCIES_MSG} ${missing_packages[*]}"
    return 1
  fi
  if ! secret=$(get-secret); then
    log-error "get-secret"
    return 1
  fi
  jq '.[0].key.privateData' --raw-output <<< ${secret} | base64 --decode -${BASE64_WRAP_SWITCH} 0
}

get-dockerconfig()
{
  if ! extract-secret-data > ${temp_dir}/pull_secret.out; then
    log-error "extract-secret-data"
    return 1
  fi

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
  local missing_packages=($(get-missing-package-dependencies "kubectl"))
  if [[ ${#missing_packages[@]} -gt 0 ]]; then
    log-error "${MISSING_PACKAGE_DEPENDENCIES_MSG} ${missing_packages[*]}"
    return 1
  fi
  log-info "Current context is $(kubectl config current-context)"
  kubectl cluster-info | head -2
}

approve-destructive-operation() {
  if [[ -z ${APPROVED+x} ]]; then
    read -p "Are you sure? [y/N] " APPROVED
  fi
  if grep -qv "^y\|Y" <<< ${APPROVED}; then
    log-info "Potentially destructive operation not approved. Override with '--auto-approve'"
    return 1 # not an error, but still an exit condition
  fi
}

create-unsafe-tls-secrets() {
  local missing_packages=($(get-missing-package-dependencies "kubectl"))
  if [[ ${#missing_packages[@]} -gt 0 ]]; then
    log-error "${MISSING_PACKAGE_DEPENDENCIES_MSG} ${missing_packages[*]}"
    return 1
  fi
  rogue_cert_name=kryptonite
  cat <<EOF > ${temp_dir}/ssl.conf
  [ req ]
  default_bits		= 2048
  distinguished_name	= req_distinguished_name
  req_extensions		= req_ext
  
  [ req_distinguished_name ]
  commonName          = ${rogue_cert_name}.elements.com
  
  [ req_ext ]
  keyUsage            = digitalSignature, keyEncipherment
  extendedKeyUsage    = serverAuth
  subjectAltName      = @alt_names
  
  [ alt_names ]
  DNS.1               = ${rogue_cert_name}.elements.com
EOF
  openssl genrsa -out ${temp_dir}/key.pem 2048 # https://gist.github.com/croxton/ebfb5f3ac143cd86542788f972434c96
  openssl req -new -key ${temp_dir}/key.pem -out ${temp_dir}/csr.pem -subj "/CN=${rogue_cert_name}.elements.com" -reqexts req_ext -config ${temp_dir}/ssl.conf
  openssl_negative_days=$(uname | grep -q Darwin && echo || echo -) # MacOS openssl doesn't support -ve days (for simulating expired certs)
  openssl x509 -req -in ${temp_dir}/csr.pem -signkey ${temp_dir}/key.pem -out ${temp_dir}/cert.pem -days ${openssl_negative_days}1 -extensions req_ext -extfile ${temp_dir}/ssl.conf
  kubectl create namespace demo-certs 2>/dev/null || true
  kubectl -n demo-certs create secret tls ${rogue_cert_name}-elements-com-tls --cert=${temp_dir}/cert.pem --key=${temp_dir}/key.pem
}

discover-tls-secrets() {
  local missing_packages=($(get-missing-package-dependencies "kubectl"))
  if [[ ${#missing_packages[@]} -gt 0 ]]; then
    log-error "${MISSING_PACKAGE_DEPENDENCIES_MSG} ${missing_packages[*]}"
    return 1
  fi
  show-cluster-status
  log-info "The following certificates were discovered:"
  kubectl get --raw /api/v1/secrets | jq -r '.items[] | select(.type == "kubernetes.io/tls") | "/namespaces/\(.metadata.namespace)/secrets/\(.metadata.name)"'
}

check-undeployed() {
  if kubectl get namespace ${1} >/dev/null 2>&1; then
    if kubectl -n ${1} rollout status deployment ${2} >/dev/null 2>&1; then
      log-info "${1}/${2} is already deployed"
    fi
  fi # if we got here, ${1}/${2} can be deployed
}

check-deployed() {
  if kubectl get namespace ${1} >/dev/null 2>&1; then
    if kubectl -n ${1} rollout status deployment ${2} >/dev/null 2>&1; then
      return 0
    fi
  fi
  log-info "${1}/${2} is not deployed"
  return 1 # not an error, but still an exit condition
}

deploy-agent() { # (legacy)
  local missing_packages=($(get-missing-package-dependencies "kubectl" "helm"))
  if [[ ${#missing_packages[@]} -gt 0 ]]; then
    log-error "${MISSING_PACKAGE_DEPENDENCIES_MSG} ${missing_packages[*]}"
    return 1
  fi

  check-undeployed jetstack-secure agent
  show-cluster-status
  approve-destructive-operation

  log-info "Deploying TLSPK agent"
  local escaped_user_secret=$(echo ${TLSPK_SA_USER_SECRET} | sed 's/\\/\\\\/g') # 1) fix forward-slashes 
  escaped_user_secret=$(echo ${escaped_user_secret} | sed 's/"/\\"/g')    # 2) fix double-quotes
  local json_creds='{"user_id": "'"${TLSPK_SA_USER_ID}"'","user_secret": "'"${escaped_user_secret}"'"}'
  local json_creds_b64=$(echo ${json_creds} | base64 -${BASE64_WRAP_SWITCH} 0)
  local tlkps_cluster_name_adj=$(tr "-" "_" <<< ${TLSPK_CLUSTER_NAME})

  get-dockerconfig > ${temp_dir}/dockerconfig.json
  helm -n jetstack-secure upgrade -i js-agent \
    oci://eu.gcr.io/jetstack-secure-enterprise/charts/jetstack-agent \
    --create-namespace \
    --version ${AGENT_VERSION} \
    --registry-config ${temp_dir}/dockerconfig.json \
    --set config.organisation="${TLSPK_ORG}" \
    --set config.cluster="${tlkps_cluster_name_adj}" \
    --set authentication.createSecret=true \
    --set authentication.secretValue="$(echo ${json_creds_b64} | sed 's/\//\\\//g')" \
    --wait

  log-info "Deploying TLSPK agent: awaiting steady state"
  sleep 5 && kubectl -n jetstack-secure wait --for=condition=Available=True --all deployments --timeout=300s
  log-info "If TLSPK agent is running, this cluster will show in TLSPK as ${tlkps_cluster_name_adj}"
}

install-operator() { # (legacy)
  local missing_packages=($(get-missing-package-dependencies "kubectl" "helm"))
  if [[ ${#missing_packages[@]} -gt 0 ]]; then
    log-error "${MISSING_PACKAGE_DEPENDENCIES_MSG} ${missing_packages[*]}"
    return 1
  fi

  check-undeployed jetstack-secure js-operator-operator
  show-cluster-status
  approve-destructive-operation
  
  log-info "Replicating secret into cluster"
  get-dockerconfig > ${temp_dir}/dockerconfig.json
  kubectl create namespace jetstack-secure 2>/dev/null || true
  kubectl -n jetstack-secure delete secret jse-gcr-creds >/dev/null 2>&1 || true
  kubectl -n jetstack-secure create secret docker-registry jse-gcr-creds --from-file .dockerconfigjson=${temp_dir}/dockerconfig.json

  log-info "Installing the operator"
  helm -n jetstack-secure upgrade -i js-operator \
    oci://eu.gcr.io/jetstack-secure-enterprise/charts/js-operator \
    --create-namespace \
    --version ${OPERATOR_VERSION} \
    --registry-config ${temp_dir}/dockerconfig.json \
    --set images.secret.enabled=true   \
    --set images.secret.name=jse-gcr-creds \
    --wait

  log-info "Installing the operator: awaiting steady state"
  sleep 5 && kubectl -n jetstack-secure wait --for=condition=Available=True --all deployments --timeout=300s
}

deploy-operator-components() { # (legacy)
  local missing_packages=($(get-missing-package-dependencies "kubectl"))
  if [[ ${#missing_packages[@]} -gt 0 ]]; then
    log-error "${MISSING_PACKAGE_DEPENDENCIES_MSG} ${missing_packages[*]}"
    return 1
  fi

  check-undeployed jetstack-secure cert-manager
  show-cluster-status
  approve-destructive-operation

  log-info "Deploy operator components (inc. cert-manager)"

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

  log-info "Deploy operator components: awaiting steady state"
  sleep 5 && kubectl -n jetstack-secure wait --for=condition=Available=True --all deployments --timeout=300s
  kubectl -n jetstack-secure wait pod -l app=cert-manager --for=condition=Ready --timeout=300s
  kubectl -n jetstack-secure wait pod -l app=webhook --for=condition=Ready --timeout=300s
}

deploy-agent-v2() {
  log-info "Ensuring ${OWNING_TEAM} is available in VCP"
  local url=https://$(get-regional-url)/v1/teams
  if [ "$(curl -X GET ${url} \
            --no-progress-meter \
            -H "accept: application/json" \
            -H "tppl-api-key: ${VCP_APIKEY}" \
            -H "Content-Type: application/json" | jq --arg t "${OWNING_TEAM}" '.teams | all(.name != $t)')" = "true" ]; then
    log-info "${OWNING_TEAM} missing, creating ..."
    curl -X POST ${url} \
      --no-progress-meter \
      -H "accept: application/json" \
      -H "tppl-api-key: ${VCP_APIKEY}" \
      -H "Content-Type: application/json" \
      -d "{\"name\":\"${OWNING_TEAM}\",\"members\":[],\"owners\":[],\"role\":\"SYSTEM_ADMIN\",\"userMatchingRules\":[]}"
    log-info "${OWNING_TEAM} successfully created"
  else
    log-info "${OWNING_TEAM} already present, not creating"
  fi

  log-info "Installing agent using venctl ${VENCTL_VERSION}"
  venctl installation cluster connect \
    --name ${TLSPK_CLUSTER_NAME} \
    --vcp-region ${VCP_REGION} \
    --api-key ${VCP_APIKEY} \
    --owning-team ${OWNING_TEAM} \
    --no-prompts
}

deploy-components-v2() {
  log-info "Ensuring image pull secret is available in VCP"
  venctl iam service-account registry create \
    --name ${TLSPK_CLUSTER_NAME}-ips \
    --vcp-region ${VCP_REGION} \
    --api-key ${VCP_APIKEY} \
    --owning-team ${OWNING_TEAM} \
    --no-prompts \
    --image-pull-secret-file venafi_registry_docker_config.json \
    --image-pull-secret-format dockerconfig \
    --scopes enterprise-cert-manager,enterprise-venafi-issuer,enterprise-approver-policy \
  
  log-info "Storing image pull secret in local cluster"
  kubectl create namespace venafi 2>/dev/null || true
  kubectl -n venafi create secret docker-registry venafi-image-pull-secret \
    --from-file .dockerconfigjson=venafi_registry_docker_config.json

  log-info "Installing components using venctl ${VENCTL_VERSION} (cert-manager=${CERT_MANAGER_VERSION} vei=${VEI_VERSION})"
  venctl components kubernetes manifest generate \
    --cert-manager --cert-manager-version ${CERT_MANAGER_VERSION} \
    --venafi-enhanced-issuer --venafi-enhanced-issuer-version ${VEI_VERSION} | \
    venctl components kubernetes manifest tool sync -f -
}

create-safe-tls-secrets() {
  local missing_packages=($(get-missing-package-dependencies "kubectl"))
  if [[ ${#missing_packages[@]} -gt 0 ]]; then
    log-error "${MISSING_PACKAGE_DEPENDENCIES_MSG} ${missing_packages[*]}"
    return 1
  fi

  check-deployed jetstack-secure cert-manager
  show-cluster-status
  approve-destructive-operation

  log-info "Creating a self-signed issuer"
  cat <<EOF > ${temp_dir}/patchfile
  spec:
    issuers:
      - name: self-signed
        clusterScope: true
        selfSigned: {}
EOF
  kubectl patch installation jetstack-secure --type merge --patch-file ${temp_dir}/patchfile
  sleep 5 # not sure we can "wait" on anything so just give the issuer a moment to appear

  log-info "Create cert-manager certs"
  kubectl create namespace demo-certs 2>/dev/null || true
  local subdomains=("hydrogen" "helium" "lithium" "beryllium" "boron" "carbon" "nitrogen" "oxygen" "fluorine" "neon")
  local durations=( "8760"     "4320"   "2160"    "720"       "240"   "120"    "96"       "24"     "6"        "1")
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
  echo "Environment Variables (REQUIRED):"
  echo "  TLSPK_SA_USER_ID           User ID of a TLSPK service account"
  echo "  TLSPK_SA_USER_SECRET       User Secret of a TLSPK service account (use single-quotes to preserve control chars!)"
  echo "  VCP_REGION                 Venafi Control Plane API Region (US or EU)"
  echo "  VCP_APIKEY                 Venafi Control Plane API Key"
  echo
  echo "Available Commands:"
  echo "  install-dependencies       Installs ALL the package dependencies required by commands in this script (jq git kubectl helm docker k3d) "
  echo "  get-oauth-token            Obtains token for TLSPK_SA_USER_ID/TLSPK_SA_USER_SECRET pair"
  echo "  get-dockerconfig           Obtains Docker-compatible registry config / image pull secret (as used with 'helm upgrade --registry-config')"
  echo "  create-local-k8s-cluster   Create a new k8s cluster on localhost (uses k3d)"
  echo "  discover-tls-secrets       Scan the current cluster for TLS secrets"
  echo "  deploy-agent               Deploys the TLSPK agent component (legacy)"
  echo "  install-operator           Installs the TLSPK operator (legacy)"
  echo "  deploy-operator-components Deploys minimal operator components, incluing cert-manager (legacy)"
  echo "  deploy-agent-v2            Deploys the TLSPK agent component"
  echo "  deploy-components-v2       Installs the TLSPK components"
  echo "  create-unsafe-tls-secrets  Define TLS Secrets in the demo-certs namespace (NOT protected by cert-manager)"
  echo "  create-safe-tls-secrets    Use cert-manager Certificate CRD to define a collection of self-signed certificates in the demo-certs namespace"
  echo
  echo "Flags:"
  echo "  --auto-approve                 Suppress prompts regarding potentially destructive operations"
  echo "  --kubectl-version <value>      Optional (default is ${KUBECTL_VERSION_DEFAULT})"
  echo "  --k3d-image-version <value>    Optional from https://hub.docker.com/r/rancher/k3s/tags (default is ${K3D_IMAGE_VERSION_DEFAULT})"
  echo "  --venctl-version <value>       Optional for v2 operations (default is ${VENCTL_VERSION_DEFAULT})"
  echo "  --cert-manager-version <value> Optional for v2 operations (default is ${CERT_MANAGER_VERSION_DEFAULT})"
  echo "  --vei-version <value>          Optional for v2 operations (default is ${VEI_VERSION_DEFAULT})"
  echo "  --cluster-name <value>         Optional for create-local-k8s-cluster (default is autogenerated or derived from 'kubectl config current-context')"
  echo "  --agent-version <value>        (legacy) Optional for deploy-agent (default is ${AGENT_VERSION_DEFAULT})"
  echo "  --operator-version <value>     (legacy) Optional for install-operator (default is ${OPERATOR_VERSION_DEFAULT})"
}

# ----- MAIN -----
trap "finally" EXIT
set -eu

if [[ "${DEBUG}" == "true" ]]; then
  set -x
fi

temp_dir=$(mktemp -d)
os=$(get-os)

if [[ $# -eq 0 ]] || grep -q '^--' <<< $1; then set "usage"; fi

args="${@}"
unset COMMAND APPROVED
while [[ $# -gt 0 ]]; do
  case $1 in
    usage | \
    install-dependencies | \
    get-oauth-token | \
    get-dockerconfig | \
    create-local-k8s-cluster | \
    discover-tls-secrets | \
    deploy-agent | \
    install-operator | \
    deploy-operator-components | \
    deploy-agent-v2 | \
    deploy-components-v2 | \
    create-unsafe-tls-secrets | \
    create-safe-tls-secrets )
      COMMAND=$1
      ;;
    --auto-approve )
      : ${APPROVED:="y"}
      ;;
    --kubectl-version )
      shift
      : ${KUBECTL_VERSION:="${1}"}
      ;;
    --k3d-image-version )
      shift
      : ${K3D_IMAGE_VERSION:="${1}"}
      ;;
    --venctl-version )
      shift
      : ${VENCTL_VERSION:="${1}"}
      ;;
    --cert-manager-version )
      shift
      : ${CERT_MANAGER_VERSION:="${1}"}
      ;;
    --vei-version )
      shift
      : ${VEI_VERSION:="${1}"}
      ;;
    --agent-version ) # (legacy)
      shift
      : ${AGENT_VERSION:="${1}"}
      ;;
    --operator-version ) # (legacy)
      shift
      : ${OPERATOR_VERSION:="${1}"}
      ;;
    --cluster-name )
      shift
      : ${TLSPK_CLUSTER_NAME:="${1}"}
      ;;
    *) 
      log-error "Unrecognised command ${args}"
      exit 1
      ;;
  esac
  shift
done

: ${KUBECTL_VERSION:=${KUBECTL_VERSION_DEFAULT}}
: ${K3D_IMAGE_VERSION:=${K3D_IMAGE_VERSION_DEFAULT}}
: ${VENCTL_VERSION:=${VENCTL_VERSION_DEFAULT}}
: ${CERT_MANAGER_VERSION:=${CERT_MANAGER_VERSION_DEFAULT}}
: ${VEI_VERSION:=${VEI_VERSION_DEFAULT}}
: ${AGENT_VERSION:=${AGENT_VERSION_DEFAULT}}
: ${OPERATOR_VERSION:=${OPERATOR_VERSION_DEFAULT}}

if ! [[ "${COMMAND}" == "create-local-k8s-cluster" ]] && kubectl config current-context >/dev/null 2>&1; then
  : ${TLSPK_CLUSTER_NAME:=$(kubectl config current-context | tr '@' '.' | cut -c-21)-$(date +"%y%m%d%H%M")}
else
  : ${TLSPK_CLUSTER_NAME:=k8s-$(date +"%y%m%d%H%M")}
fi

if ! [[ "${COMMAND}" == "usage" ]]; then
  check-vars
  derive-org-from-user
  unpatch-user-secret
fi
if ! ${COMMAND}; then
  log-error "${COMMAND} failed"
  exit 1
fi
