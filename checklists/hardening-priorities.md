# Hardening Checklist for AI Workloads in Kubernetes

**Priority-Ordered Security Controls for Supply Chain Protection**

Based on Microsoft Defender for Cloud research, March 2026

---

## 🔴 DO FIRST (This Week)

### 1. Enforce Image Signing
**Why:** Prevents poisoned images from entering your cluster  
**How:**
- Implement [Cosign](https://docs.sigstore.dev/cosign/overview/) or [Notary](https://notaryproject.dev/) for image signing
- Configure admission controller to reject unsigned images:
  ```yaml
  apiVersion: admissionregistration.k8s.io/v1
  kind: ValidatingWebhookConfiguration
  metadata:
    name: image-signature-validation
  # See full example in /examples/admission-policies/
  ```
- **Azure:** Use [Azure Policy for Kubernetes](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/policy-for-kubernetes) with built-in `[Preview]: Kubernetes cluster containers should only use allowed images` policy

**Validation:**
```bash
# Test that unsigned images are rejected
kubectl run test-unsigned --image=nginx:latest
# Should fail with "image signature validation failed"
```

---

### 2. Block Mutable Tags via Admission Control
**Why:** Same tag resolving to different digests = invisible supply chain drift  
**How:**
- Use OPA Gatekeeper or Kyverno policy:
  ```yaml
  apiVersion: kyverno.io/v1
  kind: ClusterPolicy
  metadata:
    name: require-digest-pinning
  spec:
    validationFailureAction: enforce
    rules:
    - name: check-image-digest
      match:
        resources:
          kinds:
          - Pod
      validate:
        message: "Images must be pinned to digest (image:tag@sha256:...)"
        pattern:
          spec:
            containers:
            - image: "*@sha256:*"
  ```
- **Prohibit:** `myimage:latest`, `myimage:v1.0`
- **Require:** `myimage:v1.0@sha256:abc123...`

**Validation:**
```bash
# Test that mutable tags are blocked
kubectl run test-mutable --image=nginx:latest
# Should fail with "must be pinned to digest"
```

---

### 3. Require Model Artifact Hash Validation on Load
**Why:** Prevents pickle-based RCE and backdoored model loading  
**How:**
- Add hash validation to all model loading code:
  ```python
  import hashlib
  import torch
  
  KNOWN_GOOD_HASHES = {
      "bert-base-uncased": "a1b2c3d4...",
      "llama-2-7b": "e5f6g7h8..."
  }
  
  def load_model_safe(model_path, expected_model_name):
      # Compute hash
      sha256 = hashlib.sha256()
      with open(model_path, 'rb') as f:
          for chunk in iter(lambda: f.read(4096), b""):
              sha256.update(chunk)
      computed_hash = sha256.hexdigest()
      
      # Validate against known-good
      if computed_hash != KNOWN_GOOD_HASHES[expected_model_name]:
          raise ValueError(f"Model hash mismatch! Expected {KNOWN_GOOD_HASHES[expected_model_name]}, got {computed_hash}")
      
      # Only load if hash matches
      return torch.load(model_path)
  ```
- Store known-good hashes in:
  - Azure Key Vault
  - Kubernetes Secret (with RBAC)
  - Git repo (with signature)

**Validation:**
- Manually tamper with a model file
- Verify loading fails with hash mismatch error

---

## 🟠 DO NEXT (This Month)

### 4. Prefer safetensors over Pickle for Model Files
**Why:** safetensors is a pure tensor format with no code execution primitives  
**How:**
- See the [safetensors documentation](https://github.com/huggingface/safetensors) and [HuggingFace migration guide](https://huggingface.co/docs/safetensors) for migration guidance
- Install safetensors:
  ```bash
  pip install safetensors
  ```
- Convert existing models:
  ```python
  from safetensors.torch import save_file, load_file
  import torch
  
  # Load existing .pt file
  model = torch.load("model.pt")
  
  # Save as safetensors
  save_file(model.state_dict(), "model.safetensors")
  
  # Load from safetensors
  state_dict = load_file("model.safetensors")
  model.load_state_dict(state_dict)
  ```

**Compatibility:** Works with PyTorch, TensorFlow, Flax, JAX

---

### 5. Restrict GPU Pod Privileges
**Why:** Reduces blast radius of container compromise  
**How:**
- Run GPU pods as non-root where possible:
  ```yaml
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    capabilities:
      drop:
      - ALL
  ```
- Avoid hostPath mounts unless absolutely required
- If hostPath is required, use read-only:
  ```yaml
  volumeMounts:
  - name: gpu-drivers
    mountPath: /usr/local/nvidia
    readOnly: true
  ```
- Use [RuntimeClass](https://kubernetes.io/docs/concepts/containers/runtime-class/) for GPU isolation

**Note:** Some GPU drivers require elevated privileges. Document exceptions and review quarterly.

---

### 6. Disable ServiceAccount Auto-Mount for Inference Pods
**Why:** Prevents credential theft if container is compromised  
**How:**
- For pods that don't need K8s API access:
  ```yaml
  apiVersion: v1
  kind: Pod
  metadata:
    name: inference-pod
  spec:
    automountServiceAccountToken: false
    # ... rest of spec
  ```
- Create least-privilege ServiceAccounts for pods that DO need API access
- Use [Azure Workload Identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview) instead of mounting secrets

**Validation:**
```bash
# Check which pods have auto-mounted tokens
kubectl get pods -A -o json | jq '.items[] | select(.spec.automountServiceAccountToken != false) | {namespace: .metadata.namespace, name: .metadata.name}'
```

---

## 🟢 HARDEN (Ongoing)

### 7. Enforce Network Egress Policies for AI Pods
**Why:** Model inference pods shouldn't make arbitrary outbound connections  
**How:**
- Use [Calico](https://www.tigera.io/project-calico/) or [Cilium](https://cilium.io/) NetworkPolicy:
  ```yaml
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: ai-pod-egress
    namespace: ml-prod
  spec:
    podSelector:
      matchLabels:
        app: model-server
    policyTypes:
    - Egress
    egress:
    # Allow DNS
    - to:
      - namespaceSelector:
          matchLabels:
            name: kube-system
      ports:
      - protocol: UDP
        port: 53
    # Allow specific model registry
    - to:
      - podSelector: {}
      ports:
      - protocol: TCP
        port: 443
      # Add CIDR blocks for model registry IPs
  ```
- **Block by default, allow by exception**

**Red flags:**
- Model inference pod making SMTP connections
- Training pod accessing S3 buckets in different region
- Any pod calling 169.254.169.254 (IMDS)

---

### 8. Scan Model Files Before Deployment
**Why:** Detect backdoors, malicious payloads, or tampered weights  
**How:**
- Use [modelscan](https://github.com/protectai/modelscan) in CI:
  ```bash
  pip install modelscan
  modelscan -p /path/to/model.pt
  ```
- Integrate into GitHub Actions:
  ```yaml
  - name: Scan model files
    run: |
      modelscan -p models/ --format json -o scan-results.json
      # Fail pipeline if threats found
      jq -e '.summary.total_issues == 0' scan-results.json
  ```
- **Azure:** Use [Defender for AI](https://learn.microsoft.com/en-us/azure/defender-for-cloud/ai-threat-protection) (preview) for model scanning

**Scans for:**
- Pickle exploits (__reduce__, __setstate__)
- Embedded shell code
- Suspicious imports
- Abnormal tensor shapes

---

### 9. Rotate CI Credentials on Schedule, Scope to Minimum
**Why:** Long-lived CI tokens are prime supply chain compromise targets  
**How:**
- Use short-lived OIDC tokens instead of PATs:
  - [GitHub OIDC](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
  - [Azure DevOps Workload Identity](https://learn.microsoft.com/en-us/azure/devops/pipelines/library/connect-to-azure)
- Scope CI identities to specific operations:
  ```yaml
  # Azure RBAC example
  az role assignment create \
    --assignee <CI-identity> \
    --role "AcrPush" \  # Not Contributor!
    --scope /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ContainerRegistry/registries/{acr}
  ```
- Rotate manually-created tokens every 90 days (automate via [Azure Key Vault rotation](https://learn.microsoft.com/en-us/azure/key-vault/secrets/tutorial-rotation))

**Audit:**
- List all CI/CD identities with cloud access
- Check last rotation date
- Verify minimum scope

---

## 📊 Measure Success

Track these metrics monthly:

| Metric | Target | Query |
|--------|--------|-------|
| % images with digest pinning | >95% | `kql/hunting-queries.kql` Section 0 |
| % GPU pods running as non-root | >80% | `audit-scripts/audit-ai-workloads.sh` Section 6 |
| % AI namespaces with egress policies | 100% | `kubectl get networkpolicies -A` |
| Avg CI token age | <90 days | Review in Entra ID / GitHub |
| Model files scanned in CI | 100% | CI pipeline metrics |

---

## 🔗 Related Resources

- [Microsoft Kubernetes Threat Matrix](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [OWASP Machine Learning Security Top 10](https://mltop10.info/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)

---

**Last Updated:** March 2026  
**Maintained by:** Microsoft Defender for Cloud Research Team
