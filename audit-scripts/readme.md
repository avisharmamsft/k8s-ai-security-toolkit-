# audit-ai-workloads.sh

Comprehensive security audit script for AKS clusters running AI/ML workloads. Checks cluster configuration, exposed endpoints, privileged pods, ServiceAccount permissions, ACR image security, GPU pod privileges, network policies, and Microsoft Defender coverage.

Output is written to both the console and a timestamped file: `audit-results-<YYYYMMDD_HHMMSS>.txt`

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Azure CLI | 2.50+ | [docs.microsoft.com/cli/azure/install-azure-cli](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli) |
| kubectl | any recent | [kubernetes.io/docs/tasks/tools](https://kubernetes.io/docs/tasks/tools/) |
| jq | 1.6+ | `apt install jq` / `brew install jq` |

You must be logged in to Azure CLI and have an active kubeconfig pointing at the target cluster before running:

```bash
az login
az aks get-credentials --resource-group <rg> --name <cluster>
```

---

## Required Permissions

The identity running the script needs the following:

### Azure RBAC (ARM-level)

| Role | Scope | Used for |
|------|-------|---------|
| `Reader` | Subscription or Resource Group | `az aks list/show`, `az acr list` |
| `AcrPull` or `Reader` | ACR resource | `az acr repository list/show-tags` |
| `Security Reader` | Subscription | `az security pricing list` (Defender plan status) |

> **Minimum viable:** `Reader` at subscription scope covers sections 1, 2 (ARM part), 5, and 8. `Security Reader` is additionally needed for section 8.

### Kubernetes RBAC (in-cluster)

The script reads cluster state via `kubectl`. The identity needs a ClusterRole with `get` and `list` on the following resources:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ai-security-auditor
rules:
- apiGroups: [""]
  resources:
  - pods
  - services
  - namespaces
  - serviceaccounts
  verbs: ["get", "list"]
- apiGroups: ["networking.k8s.io"]
  resources:
  - networkpolicies
  verbs: ["get", "list"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources:
  - clusterrolebindings
  - rolebindings
  verbs: ["get", "list"]
```

Bind to your identity:

```bash
kubectl create clusterrolebinding ai-audit-binding \
  --clusterrole=ai-security-auditor \
  --user=<your-entra-upn-or-sp-object-id>
```

> The script does **not** write, delete, or modify any cluster resources. All `kubectl` calls are read-only (`get`/`list`).

---

## Usage

```bash
# Audit all clusters in current subscription
bash audit-ai-workloads.sh

# Audit a specific cluster
bash audit-ai-workloads.sh --subscription <sub-id> --cluster <cluster-name> --resource-group <rg>
```

### Flags

| Flag | Description |
|------|-------------|
| `--subscription` | Azure subscription ID to target (optional — defaults to current az context) |
| `--cluster` | AKS cluster name (optional — if omitted, audits all clusters in subscription) |
| `--resource-group` | Resource group of the cluster (required if `--cluster` is set) |

---

## What Each Section Checks

| Section | What it audits |
|---------|---------------|
| 1. AKS Cluster Config | RBAC, AAD integration, Workload Identity, Defender sensor, network policy |
| 2. Exposed AI Endpoints | LoadBalancer/NodePort services in AI namespaces; all LB services cluster-wide |
| 3. Privileged Pods | `privileged: true` containers; hostPath volume mounts |
| 4. ServiceAccount Permissions | cluster-admin bindings; auto-mounted SA tokens in AI namespaces |
| 5. ACR Security | Admin user enabled; anonymous pull; public network access; `:latest` tag usage on AI images |
| 6. GPU Pod Privileges | GPU-requesting pods running privileged or as root |
| 7. Network Policies | Coverage for AI namespaces; IMDS egress block (169.254.169.254) |
| 8. Defender Coverage | Defender for Containers, ContainerRegistry, KubernetesService plan status |

---

## Customizing for Your Environment

Two variables at the top of the script control which workloads are flagged as AI/ML:

```bash
AI_NAMESPACES=("ai" "ml" "inference" "gpu" "llm" "ray" "vllm" ...)
AI_IMAGE_PATTERNS=("vllm" "ray-" "comfyui" "langflow" "ollama" ...)
```

Edit these to match your cluster's naming conventions before running.

---

## Output Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Check passed |
| ⚠️ | Warning — review recommended |
| ❌ | Critical finding — remediate immediately |
| ℹ️ | Informational |

After the run, all `❌` and `⚠️` findings are summarised at the bottom. Cross-reference `❌` findings with `checklists/hardening-priorities.md` for remediation steps.
