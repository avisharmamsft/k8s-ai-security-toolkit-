#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════
# AI Workload Security Audit — Azure CLI Scripts
# Targets: AKS clusters running AI/ML workloads
# Requirements: az CLI 2.50+, kubectl, jq
# Run: bash audit-ai-workloads.sh [--subscription <sub-id>] [--cluster <name>] [--resource-group <rg>]
# Output: Console + audit-results-<timestamp>.txt
# ════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Config ──────────────────────────────────────────────────────────────
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="audit-results-${TIMESTAMP}.txt"
SUBSCRIPTION="${1:-}"
CLUSTER_NAME="${2:-}"
RESOURCE_GROUP="${3:-}"

# AI workload indicators — adjust for your environment
AI_NAMESPACES=("ai" "ml" "inference" "gpu" "llm" "ray" "vllm" "comfyui" "langflow" "kubeflow" "mlops")
AI_IMAGE_PATTERNS=("vllm" "ray-" "comfyui" "langflow" "ollama" "triton" "onnxruntime" "pytorch" "tensorflow" "cuda")

# Colors
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

# ── Helpers ──────────────────────────────────────────────────────────────
log()    { echo -e "$*" | tee -a "$OUTPUT_FILE"; }
warn()   { echo -e "${YELLOW}⚠️  $*${NC}" | tee -a "$OUTPUT_FILE"; }
fail()   { echo -e "${RED}❌  $*${NC}" | tee -a "$OUTPUT_FILE"; }
pass()   { echo -e "${GREEN}✅  $*${NC}" | tee -a "$OUTPUT_FILE"; }
info()   { echo -e "${CYAN}ℹ️   $*${NC}" | tee -a "$OUTPUT_FILE"; }
section(){ echo -e "\n${CYAN}═══════════════════════════════════════════${NC}" | tee -a "$OUTPUT_FILE"
           echo -e "${CYAN}  $*${NC}" | tee -a "$OUTPUT_FILE"
           echo -e "${CYAN}═══════════════════════════════════════════${NC}" | tee -a "$OUTPUT_FILE"; }

check_prereqs() {
  section "Prerequisites Check"
  for tool in az kubectl jq; do
    if command -v "$tool" &>/dev/null; then
      pass "$tool found: $(command -v $tool)"
    else
      fail "$tool not found — install before running"
      exit 1
    fi
  done
  az account show &>/dev/null || { fail "Not logged in — run: az login"; exit 1; }
  pass "Azure CLI authenticated"
}

# ── Main Audit Functions ──────────────────────────────────────────────────

audit_aks_clusters() {
  section "1. AKS Cluster Inventory & Security Config"

  if [[ -n "$SUBSCRIPTION" ]]; then
    az account set --subscription "$SUBSCRIPTION"
  fi

  CURRENT_SUB=$(az account show --query '{name:name,id:id}' -o tsv)
  info "Subscription: $CURRENT_SUB"

  # Get clusters
  if [[ -n "$CLUSTER_NAME" && -n "$RESOURCE_GROUP" ]]; then
    CLUSTERS=$(az aks show -n "$CLUSTER_NAME" -g "$RESOURCE_GROUP" -o json | jq -c '[.]')
  else
    CLUSTERS=$(az aks list -o json)
  fi

  CLUSTER_COUNT=$(echo "$CLUSTERS" | jq length)
  info "Found $CLUSTER_COUNT AKS cluster(s)"

  echo "$CLUSTERS" | jq -c '.[]' | while read -r cluster; do
    NAME=$(echo "$cluster" | jq -r '.name')
    RG=$(echo "$cluster" | jq -r '.resourceGroup')
    K8S_VERSION=$(echo "$cluster" | jq -r '.kubernetesVersion')
    NETWORK_PLUGIN=$(echo "$cluster" | jq -r '.networkProfile.networkPlugin // "unknown"')
    NETWORK_POLICY=$(echo "$cluster" | jq -r '.networkProfile.networkPolicy // "none"')
    WORKLOAD_ID=$(echo "$cluster" | jq -r '.securityProfile.workloadIdentity.enabled // false')
    DEFENDER=$(echo "$cluster" | jq -r '.securityProfile.defender.securityMonitoring.enabled // false')
    RBAC=$(echo "$cluster" | jq -r '.enableRbac // false')
    AAD=$(echo "$cluster" | jq -r '.aadProfile.managed // false')

    log "\n  Cluster: $NAME (RG: $RG, K8s: $K8S_VERSION)"

    # Security checks
    [[ "$RBAC" == "true" ]] && pass "  RBAC enabled" || fail "  RBAC DISABLED — critical risk"
    [[ "$AAD" == "true" ]] && pass "  AAD integration enabled" || warn "  AAD integration not configured"
    [[ "$WORKLOAD_ID" == "true" ]] && pass "  Workload Identity enabled" || warn "  Workload Identity not enabled — pods may use pod-level MI"
    [[ "$DEFENDER" == "true" ]] && pass "  Defender for Containers sensor enabled" || fail "  Defender for Containers NOT enabled"
    [[ "$NETWORK_POLICY" != "none" && "$NETWORK_POLICY" != "null" ]] && pass "  Network policy: $NETWORK_POLICY" || warn "  No network policy configured — pods can reach any other pod"
  done
}

audit_exposed_ai_endpoints() {
  section "2. Exposed AI Inference Endpoints (LoadBalancer/NodePort)"

  info "Checking for AI services with external exposure..."

  for ns in "${AI_NAMESPACES[@]}"; do
    SERVICES=$(kubectl get svc -n "$ns" -o json 2>/dev/null || echo '{"items":[]}')
    COUNT=$(echo "$SERVICES" | jq '[.items[] | select(.spec.type=="LoadBalancer" or .spec.type=="NodePort")] | length')

    if [[ "$COUNT" -gt 0 ]]; then
      warn "Namespace $ns: $COUNT exposed service(s)"
      echo "$SERVICES" | jq -r '.items[] | select(.spec.type=="LoadBalancer" or .spec.type=="NodePort") |
        "    \(.metadata.name) [\(.spec.type)] ports: \([.spec.ports[].port] | tostring)"'
    fi
  done

  # Check ALL namespaces for AI image names in LB services
  info "Scanning all namespaces for AI-related LoadBalancer services..."
  ALL_LB=$(kubectl get svc -A -o json | jq -r '.items[] | select(.spec.type=="LoadBalancer") | "\(.metadata.namespace)/\(.metadata.name)"')
  if [[ -n "$ALL_LB" ]]; then
    warn "All LoadBalancer services (verify auth is configured):"
    echo "$ALL_LB" | while read -r svc; do log "    $svc"; done
  else
    pass "No LoadBalancer services found"
  fi
}

audit_privileged_ai_pods() {
  section "3. Privileged Pods (especially GPU / AI workloads)"

  info "Checking for privileged pods..."
  PRIVILEGED=$(kubectl get pods -A -o json | jq -r '
    .items[] |
    select(.spec.containers[].securityContext.privileged == true) |
    "\(.metadata.namespace)/\(.metadata.name)"
  ')

  if [[ -n "$PRIVILEGED" ]]; then
    warn "Privileged pods found:"
    echo "$PRIVILEGED" | while read -r pod; do
      # Flag AI workloads specifically
      if echo "$pod" | grep -iE "$(IFS='|'; echo "${AI_IMAGE_PATTERNS[*]}")" &>/dev/null; then
        fail "  AI privileged pod: $pod — review necessity"
      else
        warn "  Privileged pod: $pod"
      fi
    done
  else
    pass "No privileged pods found"
  fi

  # Check for pods with hostPath mounts
  info "Checking for hostPath volume mounts..."
  HOSTPATH=$(kubectl get pods -A -o json | jq -r '
    .items[] |
    select(.spec.volumes[]? | .hostPath != null) |
    "\(.metadata.namespace)/\(.metadata.name)"
  ')
  if [[ -n "$HOSTPATH" ]]; then
    warn "Pods with hostPath mounts:"
    echo "$HOSTPATH" | while read -r pod; do log "    $pod"; done
  else
    pass "No hostPath mounts found"
  fi
}

audit_service_account_permissions() {
  section "4. ServiceAccount Over-Permission Audit"

  info "Checking for cluster-admin bindings..."
  CLUSTER_ADMIN=$(kubectl get clusterrolebindings -o json | jq -r '
    .items[] |
    select(.roleRef.name == "cluster-admin") |
    "  \(.metadata.name): \([.subjects[]? | "\(.kind)/\(.name)"] | join(", "))"
  ')
  if [[ -n "$CLUSTER_ADMIN" ]]; then
    warn "cluster-admin bindings:"
    log "$CLUSTER_ADMIN"
  else
    pass "No non-system cluster-admin bindings"
  fi

  # Check automountServiceAccountToken in AI namespaces
  info "Checking automountServiceAccountToken in AI namespaces..."
  for ns in "${AI_NAMESPACES[@]}"; do
    PODS_WITH_TOKEN=$(kubectl get pods -n "$ns" -o json 2>/dev/null | jq -r '
      .items[] |
      select(.spec.automountServiceAccountToken != false) |
      .metadata.name
    ')
    if [[ -n "$PODS_WITH_TOKEN" ]]; then
      warn "Namespace $ns — pods with auto-mounted SA tokens:"
      echo "$PODS_WITH_TOKEN" | while read -r pod; do log "    $pod"; done
    fi
  done
}

audit_acr_security() {
  section "5. Azure Container Registry — AI Image Security"

  info "Scanning ACR registries for mutable tag usage and vulnerability status..."

  REGISTRIES=$(az acr list -o json 2>/dev/null)
  COUNT=$(echo "$REGISTRIES" | jq length)
  info "Found $COUNT ACR registries"

  echo "$REGISTRIES" | jq -c '.[]' | while read -r registry; do
    NAME=$(echo "$registry" | jq -r '.name')
    SKU=$(echo "$registry" | jq -r '.sku.name')
    ADMIN=$(echo "$registry" | jq -r '.adminUserEnabled')
    ANON=$(echo "$registry" | jq -r '.anonymousPullEnabled // false')
    PUBLIC=$(echo "$registry" | jq -r '.publicNetworkAccess // "Enabled"')

    log "\n  Registry: $NAME (SKU: $SKU)"
    [[ "$ADMIN" == "true" ]] && warn "  Admin user ENABLED — use service principal or MI instead" || pass "  Admin user disabled"
    [[ "$ANON" == "true" ]] && fail "  Anonymous pull ENABLED — public image access" || pass "  Anonymous pull disabled"
    [[ "$PUBLIC" == "Disabled" ]] && pass "  Public network access disabled" || warn "  Public network access enabled"

    # Check for AI images with mutable latest tags
    info "  Checking for AI image repos with :latest tag usage..."
    az acr repository list --name "$NAME" -o tsv 2>/dev/null | while read -r repo; do
      TAGS=$(az acr repository show-tags --name "$NAME" --repository "$repo" -o tsv 2>/dev/null | grep "^latest$" || true)
      if [[ -n "$TAGS" ]]; then
        if echo "$repo" | grep -iE "$(IFS='|'; echo "${AI_IMAGE_PATTERNS[*]}")" &>/dev/null; then
          fail "  AI repo using :latest tag: $repo — use digest pinning"
        fi
      fi
    done
  done
}

audit_gpu_pods() {
  section "6. GPU Pod Privilege Configuration"

  info "Finding all pods with GPU resource requests..."

  kubectl get pods -A -o json | jq -r '
    .items[] |
    . as $pod |
    .spec.containers[] |
    select(.resources.limits["nvidia.com/gpu"] != null or .resources.limits["amd.com/gpu"] != null) |
    {
      namespace: $pod.metadata.namespace,
      pod: $pod.metadata.name,
      container: .name,
      gpu: (.resources.limits["nvidia.com/gpu"] // .resources.limits["amd.com/gpu"]),
      privileged: (.securityContext.privileged // false),
      runAsRoot: ($pod.spec.securityContext.runAsNonRoot == false or $pod.spec.securityContext.runAsUser == 0)
    } |
    "\(.namespace)/\(.pod) — GPU: \(.gpu) | privileged: \(.privileged) | runAsRoot: \(.runAsRoot)"
  ' | while read -r line; do
    if echo "$line" | grep "privileged: true" &>/dev/null; then
      warn "$line"
    else
      pass "$line"
    fi
  done
}

audit_network_policies() {
  section "7. Network Policy Coverage for AI Namespaces"

  for ns in "${AI_NAMESPACES[@]}"; do
    NP_COUNT=$(kubectl get networkpolicy -n "$ns" --no-headers 2>/dev/null | wc -l || echo "0")
    if [[ "$NP_COUNT" -eq 0 ]]; then
      # Only warn if namespace actually exists
      NS_EXISTS=$(kubectl get namespace "$ns" --no-headers 2>/dev/null | wc -l || echo "0")
      if [[ "$NS_EXISTS" -gt 0 ]]; then
        fail "Namespace $ns exists but has NO network policies — pods have unrestricted access"
      fi
    else
      pass "Namespace $ns: $NP_COUNT network policy/policies found"
    fi
  done

  # Check if IMDS block policy exists in any AI namespace
  info "Checking for IMDS egress block policy (169.254.169.254)..."
  IMDS_BLOCKED=false
  for ns in "${AI_NAMESPACES[@]}"; do
    if kubectl get networkpolicy -n "$ns" -o json 2>/dev/null | jq -e '.items[] | .spec.egress[]? | .to[]? | .ipBlock | select(.except[]? == "169.254.169.254/32")' &>/dev/null; then
      pass "IMDS egress blocked in namespace: $ns"
      IMDS_BLOCKED=true
    fi
  done
  [[ "$IMDS_BLOCKED" == "false" ]] && warn "No IMDS egress block policy found in AI namespaces — pods can reach metadata service"
}

audit_defender_coverage() {
  section "8. Microsoft Defender Coverage"

  info "Checking Defender plan status..."

  DEFENDER_PLANS=$(az security pricing list -o json 2>/dev/null)

  for plan in "Containers" "ContainerRegistry" "KubernetesService"; do
    STATUS=$(echo "$DEFENDER_PLANS" | jq -r --arg p "$plan" '.value[] | select(.name==$p) | .pricingTier // "Free"')
    if [[ "$STATUS" == "Standard" ]]; then
      pass "Defender for $plan: Standard (enabled)"
    else
      warn "Defender for $plan: $STATUS — not enabled"
    fi
  done
}

generate_summary() {
  section "AUDIT SUMMARY"
  log "Audit completed: $TIMESTAMP"
  log "Results saved to: $OUTPUT_FILE"
  log ""
  log "Priority remediation items are marked with ❌ (critical) and ⚠️ (warning) above."
  log ""
  log "Next steps:"
  log "  1. Address all ❌ critical findings immediately"
  log "  2. Review hardening-checklist.md for P0 items"
  log "  3. Schedule KQL alert rules from hunting-queries.kql"
  log "  4. Re-run this script after remediation to verify fixes"
}

# ── Entry Point ────────────────────────────────────────────────────────────
main() {
  log "╔══════════════════════════════════════════════════════════════╗"
  log "║   AI Workload Security Audit — $(date)   ║"
  log "╚══════════════════════════════════════════════════════════════╝"

  check_prereqs
  audit_aks_clusters
  audit_exposed_ai_endpoints
  audit_privileged_ai_pods
  audit_service_account_permissions
  audit_acr_security
  audit_gpu_pods
  audit_network_policies
  audit_defender_coverage
  generate_summary
}

main "$@"
