# Extended Kubernetes + AI Threat Matrix

**Building on Microsoft's Kubernetes Threat Matrix with AI-Layer Extensions**

Base matrix: [microsoft.github.io/Threat-Matrix-for-Kubernetes](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/)  
Extensions by: Diwas Sedai & Avi Sharma, Microsoft Defender for Cloud, February 2026

---

## How to Read This Matrix

- **Black text**: Original Microsoft K8s Threat Matrix techniques
- **🟠 Orange text**: NEW AI-layer extensions we've added

The existing Kubernetes threat model remains valid. AI workloads **add new attack surface** on top of traditional K8s risks.

---

## Initial Access

| Original K8s Techniques | 🟠 AI Workload Extensions |
|-------------------------|---------------------------|
| **Using Cloud Credentials** — Compromised cloud provider credentials (AWS/Azure/GCP IAM) grant K8s access | 🟠 **Agent Framework RCE** — Langflow CVE-2025-3248, LangChain CVE-2024-36480, ComfyUI node abuse |
| **Compromised Images in Registry** — Attacker pushes backdoored image to shared registry | 🟠 **Exposed Ray/vLLM Inference Endpoints** — Ray dashboards, vLLM APIs exposed without authentication by default |
| **Kubeconfig File** — Leaked kubeconfig provides cluster access | 🟠 **MCP Server Compromise** — Malicious Model Context Protocol servers in agent dependencies |
| **Application Vulnerability** — Exploit in web app running in K8s | 🟠 **HuggingFace Model Typosquatting** — Model name confusion (e.g., `bert-base-uncased` vs `bert_base_uncased`) |
| **Exposed Sensitive Interfaces** — K8s dashboard, kubelet API exposed to internet | |

---

## Execution

| Original K8s Techniques | 🟠 AI Workload Extensions |
|-------------------------|---------------------------|
| **Exec into Container** — `kubectl exec` to run commands | 🟠 **Pickle Deserialization RCE** — `torch.load()` on .pt file with malicious `__reduce__` |
| **bash/cmd inside Container** — Shell access in running container | 🟠 **Prompt Injection → Tool Call** — Indirect injection causes agent to call `kubectl exec` autonomously |
| **New Container** — Deploy malicious container to cluster | 🟠 **MCP Server with Embedded Reverse Shell** — Malicious agent plugin executes on `npm install` or runtime |
| **Application Exploit (RCE)** — CVE in deployed application | 🟠 **LoRA Adapter Backdoor** — Fine-tuning adapter contains hidden exploit code |
| **SSH Server Running in Container** — Persistent shell access | 🟠 **Agent Tool Invocation Abuse** — Legitimate agent tools misused post-compromise |

---

## Persistence

| Original K8s Techniques | 🟠 AI Workload Extensions |
|-------------------------|---------------------------|
| **Backdoor Container** — Modify existing container with backdoor | 🟠 **Backdoored Model Weights** — Poisoned .pt/.safetensors file that re-infects on every load |
| **Writable hostPath Mount** — Persist by writing to host filesystem | 🟠 **Backdoored LoRA Adapter** — Small fine-tuning file rarely inspected, persists across deployments |
| **Kubernetes CronJob** — Scheduled task for persistent execution | 🟠 **Malicious MCP Server Auto-Loaded** — Agent framework auto-imports backdoored plugin on startup |
| **Malicious Admission Controller** — Inject code into every new pod | 🟠 **CI/CD Pipeline Poisoning** — Modify model packaging script in GitHub Actions |

---

## Privilege Escalation

| Original K8s Techniques | 🟠 AI Workload Extensions |
|-------------------------|---------------------------|
| **Privileged Container** — `privileged: true` grants host-level access | 🟠 **Agent Tool Call → kubectl exec** — Agent autonomously escalates via tool invocation |
| **Cluster-admin Binding** — Bind ServiceAccount to cluster-admin role | 🟠 **Workload Identity Federation Abuse** — Escalate from pod → Azure Contributor role |
| **hostPath Mount** — Access host filesystem from container | 🟠 **GPU Node Privilege Requirement** — GPU drivers need elevated access; compromise = node access |
| **Access Cloud Resources** — Use pod's workload identity to access cloud | |

---

## Defense Evasion

| Original K8s Techniques | 🟠 AI Workload Extensions |
|-------------------------|---------------------------|
| **Clear Container Logs** — `rm /var/log/*` to hide tracks | 🟠 **Model Payload Hidden in Tensor Format** — Malicious code embedded as weight values |
| **Delete K8s Events** — Remove audit trail | 🟠 **Inference Traffic Masks C2 Beaconing** — Malicious network calls look like model API requests |
| **Pod/Container Name Confusion** — Mimic legitimate workload names | 🟠 **Registry Tag Mutation** — Push new malicious digest under same tag (appears unchanged) |
| **Connect from Proxy Server** — Mask origin of malicious requests | |

---

## Credential Access

| Original K8s Techniques | 🟠 AI Workload Extensions |
|-------------------------|---------------------------|
| **List K8s Secrets** — `kubectl get secrets` dumps credentials | 🟠 **Agent Credential Aggregation** — Single Langflow DB contains all Azure OpenAI keys, SaaS OAuth tokens |
| **Mount ServiceAccount Token** — Read `/var/run/secrets/kubernetes.io/serviceaccount/token` | 🟠 **Azure OpenAI Key Harvest via AI Framework** — Extract from agent config/env vars |
| **Access the K8s API Server** — ServiceAccount token queries API for secrets | 🟠 **IMDS Credential Harvest from Agent Pod** — curl 169.254.169.254 from inference pod |
| **Access Cloud Resources** — Pod's workload identity accesses cloud storage/secrets | 🟠 **Model Hub API Key Leakage** — HuggingFace tokens in logs, environment variables |
| **Application Credentials in Configuration Files** — Hardcoded secrets in config | |

---

## Discovery

| Original K8s Techniques | 🟠 AI Workload Extensions |
|-------------------------|---------------------------|
| **Access the K8s API Server** — Enumerate cluster resources | 🟠 **Agent Enumerates K8s Secrets via Tool Call** — Autonomous discovery via shell/kubectl tools |
| **Access Kubelet API** — Query node-level information | 🟠 **AI Framework Exposes Cluster Topology** — MLflow/Ray dashboards reveal cluster structure |
| **Network Mapping** — Scan internal cluster network | 🟠 **Vector DB Query for Sensitive Data** — Agent searches memory store for credentials, PII |
| **Access Cloud Resources** — Discover cloud storage, databases | |

---

## Lateral Movement

| Original K8s Techniques | 🟠 AI Workload Extensions |
|-------------------------|---------------------------|
| **Access the K8s Dashboard** — Pivot from compromised pod to dashboard | 🟠 **Agent-to-Agent Protocol Poisoning** — Compromise one agent, spread via MCP/A2A protocol |
| **Cluster Internal Networking** — Move between pods/services | 🟠 **IMDS Token → Azure AD Pivot** — Pod credential escalates to Azure subscription access |
| **Application Credentials in Configuration** — Use stolen creds to access other apps | 🟠 **Compromised Agent Propagates to Other AI Namespaces** — Service mesh enables namespace traversal |
| **Writable Volume Mounts** — Access shared storage from another pod | |
| **CoreDNS Poisoning** — Redirect internal traffic | |

---

## Impact

| Original K8s Techniques | 🟠 AI Workload Extensions |
|-------------------------|---------------------------|
| **Data Destruction** — `kubectl delete` or file deletion | 🟠 **Training Data Exfiltration** — Steal proprietary datasets from storage |
| **Resource Hijacking (Cryptomining)** — Deploy miners on GPU nodes | 🟠 **Model Weight Theft** — Exfiltrate fine-tuned models (IP theft) |
| **Denial of Service** — Overload cluster resources | 🟠 **Model Poisoning** — Inject bias, backdoors, or performance degradation into production models |
| **Denial of Service (Endpoint)** — DDoS external services | 🟠 **Azure AI Foundry Resource Abuse** — Use compromised workload identity to spin up expensive AI resources |
| | 🟠 **Entra ID Backdoor → M365 Persistence** — Escalate to persistent M365 access via service principal |
| | 🟠 **Agent Autonomously Executes Destructive Actions** — Prompt injection → data deletion without human approval |

---

## Key Takeaways

1. **AI workloads expand every phase** — From Initial Access (agent framework RCEs) to Impact (model theft, autonomous destruction)
2. **Executable artifacts are the shift** — Models aren't data; they're code. Traditional container security doesn't inspect .pt files.
3. **Identity surface explosion** — ServiceAccounts + workload identity + CI tokens + agent API keys = massive credential exposure
4. **Agents create autonomous attackers** — Post-compromise, agents execute tools without human approval

---

## Detection & Mitigation Mapping

For each technique above:
- ✅ **Detection queries**: See `/kql/` directory in this repo
- 🛡️ **Mitigations**: See `/checklists/hardening-priorities.md`
- 📘 **IR playbook**: See `/playbooks/ai-supply-chain-ir.md`

---

## Credits

**Base Matrix:**  
Microsoft Kubernetes Threat Matrix Team  
[microsoft.github.io/Threat-Matrix-for-Kubernetes](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/)

**AI Extensions:**  
Diwas Sedai & Avi Sharma  
Microsoft Defender for Cloud Research Team  
February 2026

**Methodology:**  
Based on analysis of real-world incidents (ShadowRay, Langflow CVE-2025-3248, malicious MCP servers), Microsoft telemetry from production AKS clusters, and offensive security research.

---

**Version:** 1.0  
**Last Updated:** February 18, 2026  
**License:** Creative Commons Attribution 4.0 International (CC BY 4.0)
