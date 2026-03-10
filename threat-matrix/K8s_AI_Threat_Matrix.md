# Extended Kubernetes + AI Threat Matrix

**Building on Microsoft's Kubernetes Threat Matrix with AI-Layer Extensions**

Base matrix: [microsoft.github.io/Threat-Matrix-for-Kubernetes](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/)  
Interactive matrix: [interactive matrix](https://htmlpreview.github.io/?https://github.com/avisharmamsft/k8s-ai-security-toolkit/blob/c86c887597cd693153a0838cd5314f74cd169888/threat-matrix/index.html)

Extensions by: Avi Sharma, Microsoft Defender for Cloud, March 2026

<img width="2099" height="627" alt="image" src="https://github.com/user-attachments/assets/500d7d49-1eab-4af6-8a9e-d356d98e0081" />



---

## How to Read This Matrix

- **Black text**: Original Microsoft K8s Threat Matrix techniques
- **🟠 Orange text**: NEW AI-layer extensions we've added

The existing Kubernetes threat model remains valid. AI workloads **add new attack surface** on top of traditional K8s risks.

---

## Initial Access

| Original K8s Techniques | 🟠 AI Workload Extensions |
|-------------------------|---------------------------|
| **Using Cloud Credentials** — Compromised cloud provider credentials (AWS/Azure/GCP IAM) grant K8s access | 🟠 **AI Framework Remote Code Execution** — Langflow CVE-2025-3248, LangChain CVE-2025-68664 (LangGrinch), ComfyUI node abuse |
| **Compromised Images in Registry** — Attacker pushes backdoored image to shared registry | 🟠 **Unauthenticated AI Inference Endpoint Exposure** — Ray dashboards, vLLM APIs exposed without authentication by default |
| **Kubeconfig File** — Leaked kubeconfig provides cluster access | |
| **Application Vulnerability** — Exploit in web app running in K8s | |
| **Exposed Sensitive Interfaces** — K8s dashboard, kubelet API exposed to internet | |

---

## Execution

| Original K8s Techniques | 🟠 AI Workload Extensions |
|-------------------------|---------------------------|
| **Exec into Container** — `kubectl exec` to run commands | 🟠 **Pickle Deserialization Code Execution** — `torch.load()` on .pt file with malicious `__reduce__` |
| **bash/cmd inside Container** — Shell access in running container | 🟠 **Prompt Injection via Tool Call** — Indirect injection causes agent to call `kubectl exec` autonomously |
| **New Container** — Deploy malicious container to cluster | 🟠 **MCP Server with Embedded Reverse Shell** — Malicious agent plugin executes on `npm install` or runtime |
| **Application Exploit (RCE)** — CVE in deployed application | |
| **SSH Server Running in Container** — Persistent shell access | |

---

## Persistence

| Original K8s Techniques | 🟠 AI Workload Extensions |
|-------------------------|---------------------------|
| **Backdoor Container** — Modify existing container with backdoor | 🟠 **Backdoored Model Adapter Weights** — Poisoned .pt/.safetensors file that re-infects on every load |
| **Writable hostPath Mount** — Persist by writing to host filesystem | 🟠 **Malicious MCP Server Injection** — Agent framework auto-imports backdoored plugin on startup |
| **Kubernetes CronJob** — Scheduled task for persistent execution | |
| **Malicious Admission Controller** — Inject code into every new pod | |

---

## Privilege Escalation

| Original K8s Techniques | 🟠 AI Workload Extensions |
|-------------------------|---------------------------|
| **Privileged Container** — `privileged: true` grants host-level access | 🟠 **AI Tool Call Abuse for Container Exec** — Agent autonomously escalates via tool invocation |
| **Cluster-admin Binding** — Bind ServiceAccount to cluster-admin role | 🟠 **Workload identity federation abuse** — Escalate from pod → Azure Contributor role |
| **hostPath Mount** — Access host filesystem from container | |
| **Access Cloud Resources** — Use pod's workload identity to access cloud | |

---

## Defense Evasion

| Original K8s Techniques | 🟠 AI Workload Extensions |
|-------------------------|---------------------------|
| **Clear Container Logs** — `rm /var/log/*` to hide tracks | 🟠 **Model Payload Concealment in Tensor Format** — Malicious code embedded as weight values |
| **Delete K8s Events** — Remove audit trail | 🟠 **AI Inference Traffic Obfuscation** — Malicious network calls look like model API requests |
| **Pod/Container Name Confusion** — Mimic legitimate workload names | |
| **Connect from Proxy Server** — Mask origin of malicious requests | |

---

## Credential Access

| Original K8s Techniques | 🟠 AI Workload Extensions |
|-------------------------|---------------------------|
| **List K8s Secrets** — `kubectl get secrets` dumps credentials | 🟠 **AI Agent Credential Harvesting** — Single Langflow DB contains all Azure OpenAI keys, SaaS OAuth tokens |
| **Mount ServiceAccount Token** — Read `/var/run/secrets/kubernetes.io/serviceaccount/token` | 🟠 **AI Framework API Key Extraction** — Extract from agent config/env vars |
| **Access the K8s API Server** — ServiceAccount token queries API for secrets | |
| **Access Cloud Resources** — Pod's workload identity accesses cloud storage/secrets | |
| **Application Credentials in Configuration Files** — Hardcoded secrets in config | |

---

## Discovery

| Original K8s Techniques | 🟠 AI Workload Extensions |
|-------------------------|---------------------------|
| **Access the K8s API Server** — Enumerate cluster resources | 🟠 **K8s Secret Enumeration via Agent Tool Call** — Autonomous discovery via shell/kubectl tools |
| **Access Kubelet API** — Query node-level information | 🟠 **AI Framework Cluster Topology Exposure** — MLflow/Ray dashboards reveal cluster structure |
| **Network Mapping** — Scan internal cluster network | |
| **Access Cloud Resources** — Discover cloud storage, databases | |

---

## Lateral Movement

| Original K8s Techniques | 🟠 AI Workload Extensions |
|-------------------------|---------------------------|
| **Access the K8s Dashboard** — Pivot from compromised pod to dashboard | 🟠 **Agent-to-Agent Protocol Abuse** — Compromise one agent, spread via MCP/A2A protocol |
| **Cluster Internal Networking** — Move between pods/services | 🟠 **IMDS-Based Cloud Identity Pivot** — Pod credential escalates to Azure subscription access |
| **Application Credentials in Configuration** — Use stolen creds to access other apps | |
| **Writable Volume Mounts** — Access shared storage from another pod | |
| **CoreDNS Poisoning** — Redirect internal traffic | |

---

## Impact

| Original K8s Techniques | 🟠 AI Workload Extensions |
|-------------------------|---------------------------|
| **Data Destruction** — `kubectl delete` or file deletion | 🟠 **GPU Cryptomining via Job API** — Ray job or K8s Job submission runs GPU miner on A100/H100 nodes |
| **Resource Hijacking (Cryptomining)** — Deploy miners on GPU nodes | 🟠 **Model Weight Exfiltration** — Exfiltrate proprietary .safetensors/.pt files representing significant IP |
| **Denial of Service** — Overload cluster resources | 🟠 **Entra ID Persistence via Backdoor Account** — IMDS token → new app registration → persistent M365 access |
| **Denial of Service (Endpoint)** — DDoS external services | |

---

## Key Takeaways

1. **AI workloads expand every phase** — From Initial Access (agent framework RCEs) to Impact (model theft, autonomous destruction)
2. **Executable artifacts are the shift** — Models aren't data; they're code. Traditional container security doesn't inspect .pt files.
3. **Identity surface explosion** — ServiceAccounts + workload identity + CI tokens + agent API keys = massive credential exposure
4. **Agents create autonomous attackers** — Post-compromise, agents execute tools without human approval

---

## AI Workload Mitigations (AI-M)

The following mitigations are specific to AI/ML workloads in Kubernetes environments. They use the `AI-M` prefix to distinguish from the base [Microsoft K8s mitigations (MS-M9001–MS-M9032)](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/mitigations/). Each technique above references applicable AI-M and MS-M IDs — see the interactive matrix for per-technique mappings.

| ID | Name | Description |
|----|------|-------------|
| **AI-M001** | Require authentication on AI framework endpoints | Enforce auth on all AI framework APIs and dashboards (Ray, vLLM, Ollama, Langflow) before exposing them via NetworkPolicy and service-level auth. |
| **AI-M002** | Block IMDS access from AI namespaces | Egress NetworkPolicy denying `169.254.169.254/32` from inference pods prevents credential harvesting from the Azure Instance Metadata Service. |
| **AI-M003** | Enforce model artifact integrity | Verify `.safetensors`/`.pt` files via hash pinning or sigstore before load. Block raw pickle-format `.pt` files in production environments. |
| **AI-M004** | Restrict runtime package installation | OPA/Gatekeeper policy blocking `pip`/`npm` exec at runtime; enforce immutable container filesystems so supply chain attacks can't install packages post-deploy. |
| **AI-M005** | Scope AI workload identities to minimum required permissions | Assign a separate Workload Identity per AI component scoped to specific resource IDs — not subscription-wide Contributor or Owner roles. |
| **AI-M006** | Sandbox AI framework tool permissions | Explicitly allowlist tools available to agents; deny `kubectl`/`az`/shell access unless required. Require human-in-the-loop approval for destructive or privileged actions. |
| **AI-M007** | Isolate AI namespaces with NetworkPolicy | Apply default-deny ingress/egress NetworkPolicies to all AI namespaces. Permit only explicitly required service-to-service paths. |
| **AI-M008** | Scan and gate model artifacts in registry | Scan model files for pickle exploits and embedded malware before publishing. Enforce digest pinning; prohibit `:latest` tags in production. |
| **AI-M009** | Protect AI framework credential stores | Store API keys in Azure Key Vault — not in `.env` files, environment variables, or plaintext config. Encrypt LangChain/AutoGen configs at rest. |
| **AI-M010** | Monitor and alert on AI-specific process patterns | Enable Defender for Containers with custom alert rules for: `pip install` at runtime, IMDS calls from inference pods, shell spawns from AI framework processes, and large blob transfers from model storage. |

### Technique → Mitigation Mapping

| Technique | AI-M | MS-M (base layer) |
|-----------|------|-------------------|
| AI-IA-001 AI Framework RCE | AI-M001, AI-M007 | [MS-M9008](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9008%20Limit%20Access%20to%20Services%20Over%20Network/), [MS-M9009](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9009%20Require%20Strong%20Authentication%20to%20Services/), [MS-M9014](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9014%20Network%20Segmentation/) |
| AI-IA-002 Unauthenticated Endpoint Exposure | AI-M001, AI-M007 | [MS-M9008](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9008%20Limit%20Access%20to%20Services%20Over%20Network/), [MS-M9009](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9009%20Require%20Strong%20Authentication%20to%20Services/), [MS-M9015](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9015%20Avoid%20Running%20Management%20Interface%20on%20Containers/) |
| AI-EX-001 Pickle Deserialization Code Execution | AI-M003, AI-M008 | [MS-M9005](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9005/), [MS-M9012](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9012%20Remove%20Tools%20from%20Container%20Images/) |
| AI-EX-002 Prompt Injection via Tool Call | AI-M006 | [MS-M9003](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9003%20Adhere%20to%20least-privilege%20principle/), [MS-M9010](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9010%20Restrict%20Exec%20Commands%20on%20Pods/) |
| AI-EX-003 MCP Server with Embedded Reverse Shell | AI-M004, AI-M008 | [MS-M9005](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9005/), [MS-M9012](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9012%20Remove%20Tools%20from%20Container%20Images/) |
| AI-PE-001 Backdoored Model Adapter Weights | AI-M003, AI-M008 | [MS-M9005](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9005/), [MS-M9016](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9016%20Restrict%20File%20and%20Directory%20Permissions/) |
| AI-PE-002 Malicious MCP Server Injection | AI-M004 | [MS-M9005](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9005/), [MS-M9016](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9016%20Restrict%20File%20and%20Directory%20Permissions/) |
| AI-PRIV-001 AI Tool Call Abuse for Container Exec | AI-M006 | [MS-M9003](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9003%20Adhere%20to%20least-privilege%20principle/), [MS-M9010](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9010%20Restrict%20Exec%20Commands%20on%20Pods/), [MS-M9013](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9013%20Restrict%20over%20permissive%20containers/) |
| AI-PRIV-002 Workload Identity Federation Abuse | AI-M005 | [MS-M9003](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9003%20Adhere%20to%20least-privilege%20principle/), [MS-M9019](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9019%20Allocate%20specific%20identities%20to%20pods/) |
| AI-DE-001 Model Payload Concealment in Tensor Format | AI-M008 | [MS-M9005](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9005/) |
| AI-DE-002 AI Inference Traffic Obfuscation | AI-M007, AI-M010 | [MS-M9007](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9007%20Network%20Intrusion%20Prevention/), [MS-M9014](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9014%20Network%20Segmentation/) |
| AI-CA-001 AI Agent Credential Harvesting | AI-M006, AI-M009 | [MS-M9022](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9022%20Use%20Managed%20Secret%20Store/), [MS-M9025](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9025%20Disable%20Service%20Account%20Auto%20Mount/), [MS-M9026](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9026%20Avoid%20using%20plain%20text%20credentials%20in%20configuration%20files/) |
| AI-CA-002 AI Framework API Key Extraction | AI-M009 | [MS-M9022](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9022%20Use%20Managed%20Secret%20Store/), [MS-M9026](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9026%20Avoid%20using%20plain%20text%20credentials%20in%20configuration%20files/) |
| AI-DI-001 K8s Secret Enumeration via Agent Tool Call | AI-M006 | [MS-M9003](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9003%20Adhere%20to%20least-privilege%20principle/), [MS-M9010](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9010%20Restrict%20Exec%20Commands%20on%20Pods/) |
| AI-DI-002 AI Framework Cluster Topology Exposure | AI-M006, AI-M007 | [MS-M9003](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9003%20Adhere%20to%20least-privilege%20principle/), [MS-M9014](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9014%20Network%20Segmentation/) |
| AI-LM-001 Agent-to-Agent Protocol Abuse | AI-M006, AI-M007 | [MS-M9003](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9003%20Adhere%20to%20least-privilege%20principle/), [MS-M9014](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9014%20Network%20Segmentation/) |
| AI-LM-002 IMDS-Based Cloud Identity Pivot | AI-M002, AI-M005 | [MS-M9018](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9018%20Restricting%20cloud%20metadata%20API%20access/), [MS-M9019](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9019%20Allocate%20specific%20identities%20to%20pods/) |
| AI-IM-001 GPU Cryptomining via Job API | AI-M006, AI-M007 | [MS-M9003](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9003%20Adhere%20to%20least-privilege%20principle/), [MS-M9013](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9013%20Restrict%20over%20permissive%20containers/), [MS-M9029](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9029%20Set%20requests%20and%20limits%20for%20containers/) |
| AI-IM-002 Model Weight Exfiltration | AI-M007, AI-M010 | [MS-M9014](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9014%20Network%20Segmentation/), [MS-M9016](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9016%20Restrict%20File%20and%20Directory%20Permissions/) |
| AI-IM-003 Entra ID Persistence via Backdoor Account | AI-M005, AI-M010 | [MS-M9019](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9019%20Allocate%20specific%20identities%20to%20pods/), [MS-M9020](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/MS-M9020%20Collect%20Logs%20to%20Remote%20Data%20Storage/) |

> **Detection queries**: See `kql/` directory in this repo  
> **Hardening checklist**: See `checklists/hardening-priorities.md`

---

## Credits

**Base Matrix:**  
The threat matrix for Kubernetes is created by Yossi Weizman, Dotan Patrich and Ram Pliskin of the Microsoft Defender for Cloud team.  
[microsoft.github.io/Threat-Matrix-for-Kubernetes](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/)

**AI Extensions:**  
Avi Sharma  
Microsoft Defender for Cloud Research Team  
March 2026

**Methodology:**  
Based on analysis of real-world incidents (ShadowRay, Langflow CVE-2025-3248, malicious MCP servers), Microsoft telemetry from production AKS clusters, and offensive security research.

---

## License

This work is an adaptation of the [Microsoft Threat Matrix for Kubernetes](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/) by Yossi Weizman, Dotan Patrich, and Ram Pliskin, licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).

The AI-layer extensions (techniques prefixed `AI-`, mitigations prefixed `AI-M`, and associated KQL detection queries) are original contributions by Avi Sharma and the Microsoft Defender for Cloud Research Team, and are also made available under **CC BY 4.0**.

**You are free to:**
- Share — copy and redistribute this material in any medium or format
- Adapt — remix, transform, and build upon the material for any purpose, even commercially

**Under the following terms:**
- **Attribution** — You must give appropriate credit to both the original Microsoft Threat Matrix for Kubernetes and this work, provide a link to the license, and indicate if changes were made.

[![CC BY 4.0](https://licensebuttons.net/l/by/4.0/88x31.png)](https://creativecommons.org/licenses/by/4.0/)

---

**Version:** 1.0  
**Last Updated:** March, 2026  

