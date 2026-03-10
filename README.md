# K8s AI Security Toolkit

**Supply Chain Security Resources for AI Workloads in Kubernetes**

Presented at Microsoft Defender Experts S.T.A.R. Forum, March 2026

**Authors:**
- Avi Sharma, Security Researcher, Microsoft Defender for Cloud
- Diwas Sedai, Senior Security Researcher, Microsoft Defender for Cloud

---

## 📦 What's in This Repo

This repository contains production-ready security resources for detecting and defending against supply chain attacks targeting AI workloads in Kubernetes clusters.

### 1. **Extended Kubernetes + AI Threat Matrix**
- `threat-matrix/K8s_AI_Threat_Matrix.md` - Markdown version
- `threat-matrix/K8s_AI_Threat_Matrix.xlsx` - Excel version with filtering
- Shows base Kubernetes threat techniques (from [Microsoft's K8s Threat Matrix](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/))
- **NEW:** AI-layer extensions covering model artifacts, agentic systems, and ML-specific attack paths

### 2. **Azure CLI Audit Scripts**
- `scripts/enumerate-exposed-endpoints.sh` - Find publicly exposed AI framework endpoints (Ray, MLflow, Langflow)
- `scripts/audit-service-accounts.sh` - Identify over-permissioned ServiceAccounts with cloud access
- `scripts/detect-mutable-tags.sh` - Find images using mutable tags (not pinned to digest)
- `scripts/gpu-pod-privileges.sh` - Enumerate GPU pods with elevated privileges

**Requirements:** Azure CLI, jq, kubectl

### 3. **KQL Hunting Query Pack**
- `kql/01-python-spawning-shell.kql` - Python processes spawning bash/curl in GPU pods
- `kql/02-metadata-endpoint-access.kql` - IMDS credential harvesting detection
- `kql/03-mutable-tag-drift.kql` - Registry tag mutation over time
- `kql/04-runtime-pip-install.kql` - Dependency confusion via runtime package installs
- `kql/05-langflow-rce-detection.kql` - CVE-2025-3248 exploit attempts
- `kql/06-multi-dataset-correlation.kql` - **ADVANCED:** Correlates K8s audit + process events + ARM logs + Entra logs
- `kql/07-identify-ai-workloads.kql` - **NEW:** How to identify AI workloads in your clusters

**Schema:** Adapted for Azure Log Analytics (AKS), Defender for Cloud, and Sentinel

### 4. **Hardening Checklist**
- `checklists/hardening-priorities.md` - Prioritized checklist with links to tooling
- `checklists/hardening-checklist.pdf` - Printable PDF version

**Categories:**
- 🔴 **Do First (This Week):** Image signing, mutable tag blocking, model hash validation
- 🟠 **Do Next (This Month):** safetensors migration, GPU pod privilege reduction, ServiceAccount auto-mount
- 🟢 **Harden (Ongoing):** Network egress policies, CI credential rotation, model file scanning

### 5. **safetensors Migration Guide**
- `guides/pickle-to-safetensors.md` - Step-by-step migration from PyTorch .pt (pickle) to safetensors
- Includes code examples, compatibility notes, and validation scripts

### 6. **Incident Response Playbook**
- `playbooks/ai-supply-chain-ir.md` - 6-step IR playbook for AI supply chain incidents
- `playbooks/ai-supply-chain-ir.pdf` - Printable version

**Steps:**
1. Validate Artifact Integrity
2. Identify Affected Scope
3. Detect Runtime Anomalies
4. Assess Credential Exposure
5. Rotate Secrets & Rebuild
6. Enforce Artifact Signing

---

## 🎯 Quick Start

### Identify AI Workloads in Your Cluster

```kql
// Run in Azure Log Analytics
K8S_ProcessEvents
| where pname has_any ("python", "python3", "uvicorn", "gunicorn")
| where cmdline has_any ("torch", "tensorflow", "transformers", "langchain", "openai")
| summarize WorkloadCount=dcount(PodName), 
            DistinctCommands=make_set(cmdline, 10)
            by Namespace, Image
| where WorkloadCount > 0
| project Namespace, Image, WorkloadCount, DistinctCommands
```

### Detect Python→Shell in GPU Pods (High-Severity IOC)

```kql
K8S_ProcessEvents
| where cmdline has_any ("bash", "sh", "/bin/sh", "curl", "wget")
| where pname has_any ("python", "python3", "uvicorn")
| where Namespace has_any ("ml-", "ai-", "gpu-")  // adjust to your naming
| project TimeCreatedUtc, PodName, Namespace, cmdline, pname, user
```

---

## 🔗 Related Resources

- [Microsoft Kubernetes Threat Matrix](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (includes Langflow CVE-2025-3248)
- [safetensors Documentation](https://github.com/huggingface/safetensors)
- [Cosign (Sigstore)](https://docs.sigstore.dev/cosign/overview/)
- [Azure Defender for Containers](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction)

---

## 📝 Citation

If you use these resources in your research or security operations, please cite:

```
Sedai, D., & Sharma, A. (2026). Supply Chain Attacks on AI Workloads in Kubernetes.
Microsoft Defender Experts S.T.A.R. Forum. https://github.com/[your-repo-path]
```

---

## ⚠️ Disclaimer

These tools and techniques are provided for **defensive security research and legitimate security operations only**. The authors and Microsoft are not responsible for misuse. Always obtain proper authorization before conducting security assessments.

---

## 📧 Contact

Questions or feedback? Reach out via:
- GitHub Issues on this repo
- Microsoft Security Community forums

---

**Last Updated:** March 2026  
**License:** MIT (see LICENSE file)
