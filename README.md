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
- `threat-matrix/threat-matrix.xlsx` - Excel version with filtering
- `threat-matrix/index.html` - [Interactive version](https://htmlpreview.github.io/?https://github.com/avisharmamsft/k8s-ai-security-toolkit/blob/d996d27762d046b471358d15ae125180f2a5c5a6/threat-matrix/index.html)
- Shows base Kubernetes threat techniques (from [Microsoft's K8s Threat Matrix](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/))
- **NEW:** AI-layer extensions covering model artifacts, agentic systems, and ML-specific attack paths

### 2. **Azure CLI Audit Script**
- `audit-scripts/audit-ai-workloads.sh` - Comprehensive AKS security audit covering exposed endpoints, over-permissioned ServiceAccounts, mutable image tags, and GPU pod privileges

**Requirements:** Azure CLI 2.50+, jq, kubectl

### 3. **KQL Hunting Query Pack**
- `kql/hunting-queries.kql` - Full query pack (9 sections, 20+ queries) covering:
  - **Section 0** - AI workload discovery (namespace, image, GPU, Security Explorer)
  - **Section 1** - Runtime pip/npm installs (dependency confusion, malicious postinstall patterns)
  - **Section 2** - IMDS token harvest and az CLI pivot
  - **Section 3** - AI framework process anomalies (kubectl abuse, LangGrinch CVE-2025-68664, pickle deserialization)
  - **Section 4** - Sidecar injection and webhook abuse
  - **Section 5** - CI/CD pipeline dependency drift
  - **Section 6** - Cryptomining in AI/GPU pods
  - **Section 7** - Sentinel / Log Analytics queries (SecurityAlert, kube-audit, Entra AuditLogs)
  - **Section 8** - Scheduled alert rule templates
  - **Section 9** - Agent tool-call drift baseline and CI SPN pivot detection
- `kql/06-multi-dataset-correlation.kql` - **ADVANCED:** Full kill-chain correlation across K8s audit + process events + ARM logs + Entra sign-in logs
- `kql/07-identify-ai-workloads.kql` - **NEW:** Multi-method AI workload inventory with risk scoring

**Schema:** Microsoft Defender XDR Advanced Hunting (`CloudProcessEvents`, `CloudAuditEvents`) + Sentinel (`AzureActivity`, `SigninLogs`, `AzureDiagnostics`)

### 4. **Hardening Checklist**
- `checklists/hardening-priorities.md` - Prioritized checklist with implementation examples and links to tooling

**Categories:**
- 🔴 **Do First (This Week):** Image signing, mutable tag blocking, model hash validation
- 🟠 **Do Next (This Month):** safetensors migration, GPU pod privilege reduction, ServiceAccount auto-mount
- 🟢 **Harden (Ongoing):** Network egress policies, CI credential rotation, model file scanning

---

## 🎯 Quick Start

### Identify AI Workloads in Your Cluster

Run in **Defender XDR > Advanced Hunting:**

```kql
// Discover AI/ML workloads by framework signature
CloudProcessEvents
| where Timestamp > ago(7d)
| where FileName has_any ("python", "python3", "uvicorn", "gunicorn")
| where ProcessCommandLine has_any ("torch", "tensorflow", "transformers", "langchain", "openai")
| summarize WorkloadCount=dcount(KubernetesPodName),
            DistinctCommands=make_set(ProcessCommandLine, 10)
            by KubernetesNamespace, ContainerImageName
| where WorkloadCount > 0
| project KubernetesNamespace, ContainerImageName, WorkloadCount, DistinctCommands
```

### Detect Python→Shell in AI Pods (High-Severity IOC)

Run in **Defender XDR > Advanced Hunting:**

```kql
CloudProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("bash", "sh", "/bin/sh", "curl", "wget")
| where FileName has_any ("python", "python3", "uvicorn")
| where KubernetesNamespace has_any ("ml-", "ai-", "gpu-")  // adjust to your naming
| project Timestamp, KubernetesPodName, KubernetesNamespace,
          ProcessCommandLine, FileName, AccountName
```

---

## 🔗 Related Resources

- [Microsoft Kubernetes Threat Matrix](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (includes Langflow CVE-2025-3248)
- [safetensors Documentation](https://github.com/huggingface/safetensors)
- [Cosign (Sigstore)](https://docs.sigstore.dev/cosign/overview/)
- [Azure Defender for Containers](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction)
- [CloudProcessEvents schema reference](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudprocessevents-table)
- [CloudAuditEvents schema reference](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudauditevents-table)

---

## 📝 Citation

If you use these resources in your research or security operations, please cite:

```
Sharma, A. (2026). Supply Chain Attacks on AI Workloads in Kubernetes.
Microsoft Defender Experts S.T.A.R. Forum. https://github.com/avisharmamsft/k8s-ai-security-toolkit
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
