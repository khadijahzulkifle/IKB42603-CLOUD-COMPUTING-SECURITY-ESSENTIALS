# Lab 2: Secure Isolation & Multi-Tenancy

**Course:** IKB42603 Cloud Computing Security Essentials  
**Lab:** Lab 2  
**Topic:** Secure Isolation & Multi-Tenancy — Compute, Network and Storage Isolation  
**Environment:** Kali Linux, Docker, kind, kubectl, Kubernetes with Calico  
**Name:** Khadijah

---

# Objective

The objective of this lab is to understand and demonstrate secure isolation and multi-tenancy in a Kubernetes environment. The lab separates tenants using Kubernetes namespaces, demonstrates the default-open communication risk between namespaces, applies ResourceQuota to control shared resources, implements NetworkPolicy for network isolation, and uses Kubernetes RBAC to protect tenant secrets. The lab also demonstrates data remanence and secure deletion using a Docker volume.

The lab uses a kind Kubernetes cluster with the default CNI disabled and Calico installed so that NetworkPolicy enforcement can be demonstrated.

---

# Learning Outcomes

At the end of this lab, the following learning outcomes were demonstrated:

1. Demonstrate compute isolation by separating tenants into Kubernetes namespaces.
2. Observe the default-open behaviour of shared infrastructure and explain its security risk.
3. Implement network isolation using a default-deny NetworkPolicy.
4. Enforce storage and secret isolation using Kubernetes RBAC.
5. Explain data remanence and demonstrate secure deletion.

---

# Environment

- Operating System: Kali Linux
- Docker
- kind
- kubectl
- Kubernetes
- Calico CNI
- Kali Linux Terminal

---


# Step-by-Step Implementation

## Task 1: Two Tenants on One Cluster

Task 1 models two customers as separate Kubernetes namespaces sharing the same physical cluster infrastructure.

### Step 1: Create Tenant Namespaces

**Commands**

```bash
kubectl create namespace tenant-a
kubectl create namespace tenant-b
```

**Verification**

```bash
kubectl get namespaces
```

**Result**

The `tenant-a` and `tenant-b` namespaces were created successfully.

**Figure 3:** Tenant namespaces created

---

### Step 2: Deploy Web Applications

A simple NGINX web server was deployed for each tenant.

**Commands**

```bash
kubectl -n tenant-a create deployment web --image=nginx
kubectl -n tenant-b create deployment web --image=nginx
```

**Result**

The `web` deployment was created in both tenant namespaces.

---

### Step 3: Expose the Web Applications

**Commands**

```bash
kubectl -n tenant-a expose deployment web --port=80
kubectl -n tenant-b expose deployment web --port=80
```

**Verification**

```bash
kubectl get pods,svc -n tenant-a
kubectl get pods,svc -n tenant-b
```

**Result**

Both tenants had their own NGINX Pod and Service.

**Figure 4:** Pods and Services for tenant-a and tenant-b

> ![alt text](<task 1-1.png>)

---

## Task 2: Observe the Default-Open Risk

Task 2 demonstrates that pods in different namespaces can communicate with each other by default when no NetworkPolicy is applied.

### Step 1: Get Tenant-B Service IP

**Command**

```bash
kubectl get svc web -n tenant-b -o jsonpath='{.spec.clusterIP}'; echo
```

**Observed Tenant-B Service IP**

```text
10.96.23.19
```

---

### Step 2: Test Cross-Tenant Communication

The probe was launched from `tenant-a` to access the web service in `tenant-b`.

**Command**

```bash
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never -- curl -s -m 5 http://10.96.23.19 -o /dev/null -w 'HTTP %{http_code}\n'
```

**Result**

```text
HTTP 200
```

The HTTP 200 response demonstrated that `tenant-a` could reach the service in `tenant-b` before network isolation was applied.

**Figure 5:** Task 2 — Default-open cross-tenant communication (HTTP 200)

> ![alt text](<task 2-1.png>)

### Security Explanation

The successful HTTP 200 response demonstrates the default-open behaviour of the shared Kubernetes network. Namespace separation alone does not automatically prevent network communication between tenants. In a multi-tenant environment, this could allow one tenant to communicate with services belonging to another tenant.

---

## Task 3: Contain the Noisy Neighbour with ResourceQuota

Task 3 demonstrates resource isolation by limiting how many shared Kubernetes resources `tenant-a` can request.

### Step 1: Create ResourceQuota

**Command**

```bash
kubectl apply -f <(printf 'apiVersion: v1\nkind: ResourceQuota\nmetadata:\n  name: tenant-a-quota\n  namespace: tenant-a\nspec:\n  hard:\n    requests.cpu: "1"\n    requests.memory: 512Mi\n    pods: "5"\n')
```

**Result**

The `tenant-a-quota` ResourceQuota was created successfully.

The quota limits were:

- Maximum CPU requests: `1`
- Maximum memory requests: `512Mi`
- Maximum number of Pods: `5`

### Step 2: Verify the ResourceQuota

**Command**

```bash
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

**Figure 6:** Task 3 — ResourceQuota applied to tenant-a

> ![alt text](<task 3.png>)

### Explanation

ResourceQuota prevents one tenant from consuming excessive shared resources. This reduces the noisy-neighbour risk and helps maintain fair resource allocation between tenants.

---

## Task 4: Default-Deny Network Isolation

Task 4 applies a default-deny ingress NetworkPolicy to `tenant-b`.

### Step 1: Apply Default-Deny NetworkPolicy

**Command**

```bash
kubectl apply -f <(printf 'apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: default-deny-ingress\n  namespace: tenant-b\nspec:\n  podSelector: {}\n  policyTypes:\n  - Ingress\n')
```

**Result**

The `default-deny-ingress` NetworkPolicy was successfully created in `tenant-b`.

---

### Step 2: Re-Test Cross-Tenant Communication

Because the ResourceQuota requires CPU and memory requests, a temporary probe Pod was created with resource requests.

**Command**

```bash
printf '%s\n' 'apiVersion: v1' 'kind: Pod' 'metadata:' '  name: probe' '  namespace: tenant-a' 'spec:' '  restartPolicy: Never' '  containers:' '  - name: probe' '    image: curlimages/curl' '    resources:' '      requests:' '        cpu: 100m' '        memory: 64Mi' '    command: ["sleep","30"]' | kubectl apply -f -
```

The request was then tested with:

```bash
kubectl exec -n tenant-a probe -- curl -s -m 5 http://10.96.23.19 -o /dev/null -w 'HTTP %{http_code}\n'
```

**Observed Result**

```text
HTTP 000
command terminated with exit code 28
```

The connection timed out after the NetworkPolicy was applied.

**Figure 7:** Task 4 — Cross-tenant traffic blocked after NetworkPolicy

> ![alt text](<task 4.png>)

### Before-and-After Comparison

| Test | Result | Meaning |
|---|---|---|
| Before NetworkPolicy | HTTP 200 | tenant-a could reach tenant-b |
| After NetworkPolicy | HTTP 000 / timeout | Cross-tenant ingress was blocked |

### Security Explanation

The default-deny NetworkPolicy implements the principle of denying traffic by default and allowing communication only when explicitly permitted. The before-and-after results provide evidence that network isolation was successfully enforced.

After testing, the temporary probe Pod was removed:

```bash
kubectl delete pod probe -n tenant-a
```

---

## Task 5: Storage & Secret Isolation

Task 5 demonstrates storage and secret isolation using Kubernetes Secrets and RBAC.

### Step 1: Create Secrets

**Commands**

```bash
kubectl -n tenant-a create secret generic data --from-literal=value=SECRET_A
kubectl -n tenant-b create secret generic data --from-literal=value=SECRET_B
```

**Result**

A separate `data` Secret was created in each tenant namespace.

---

### Step 2: Create Service Account

**Command**

```bash
kubectl -n tenant-a create serviceaccount app-a
```

**Result**

The `app-a` ServiceAccount was created in `tenant-a`.

---

### Step 3: Create Reader Role

**Command**

```bash
kubectl -n tenant-a create role reader --verb=get --resource=secrets
```

The Role grants only the `get` permission for Secrets in the `tenant-a` namespace.

---

### Step 4: Create RoleBinding

**Command**

```bash
kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a
```

The RoleBinding connects the `app-a` ServiceAccount to the `reader` Role.

---

### Step 5: Verify Permissions

**Tenant-A test**

```bash
kubectl auth can-i get secrets -n tenant-a --as=system:serviceaccount:tenant-a:app-a
```

**Expected Result**

```text
yes
```

**Tenant-B test**

```bash
kubectl auth can-i get secrets -n tenant-b --as=system:serviceaccount:tenant-a:app-a
```

**Expected Result**

```text
no
```

**Figure 8:** Task 5 — RBAC permission testing

> ![alt text](<task 5a.png>)
>![alt text](<task 5b.png>)
### Explanation

The RBAC configuration provides namespace-level secret isolation. The `app-a` ServiceAccount is allowed to retrieve Secrets in `tenant-a`, but it is not authorized to retrieve Secrets from `tenant-b`. This demonstrates the principle of least privilege and prevents one tenant from accessing another tenant's secrets.

---

## Task 6: Data Remanence & Secure Deletion

Task 6 demonstrates data remanence by creating and normally deleting a file inside a Docker volume, followed by an overwrite-before-delete operation.

### Step 1: Normal Deletion Test

**Command**

```bash
docker run --rm -v ccse-vol:/data alpine sh -c 'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; rm /data/phi.txt; grep -a SENSITIVE /data/* 2>/dev/null; echo scan-done'
```

**Observed Result**

```text
scan-done
```

**Figure 9:** Task 6 — Data remanence scan after normal deletion

---

### Step 2: Secure Wipe

**Command**

```bash
docker run --rm -v ccse-vol:/data alpine sh -c 'echo SENSITIVE > /data/phi2.txt; sync; dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; rm /data/phi2.txt; echo wiped'
```

**Expected Result**

```text
wiped
```

**Figure 10:** Task 6 — Secure wipe output

> ![alt text](<task 6-1.png>)

### Explanation

Data remanence refers to the possibility that data may remain recoverable after normal deletion. The lab demonstrates overwriting the file before deletion as a secure deletion technique.

In cloud storage, physical block control is normally unavailable to the tenant. Therefore, the lab manual identifies cryptographic erasure, such as destroying the encryption key, as the practical cloud solution to data remanence.

---

# Verification

The following commands can be used to verify the isolation controls.

### Verify NetworkPolicies

```bash
kubectl get networkpolicy -A
```

### Verify ResourceQuota

```bash
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

**Figure 11:** Final Kubernetes isolation verification

> **[INSERT SCREENSHOT HERE]**

---

# Short-Answer Questions

## Q1. Why can containers in different namespaces reach each other by default, and why is that dangerous in multi-tenant cloud?

Kubernetes namespaces provide logical separation of resources, but they do not automatically block network communication between Pods in different namespaces. Without a NetworkPolicy, a Pod in one tenant can communicate with services or Pods belonging to another tenant. This is dangerous in a multi-tenant cloud because it can increase the risk of unauthorized communication, service discovery, lateral movement, and exposure of another tenant's services.

---

## Q2. Explain the default-deny principle and how your NetworkPolicy implements it.

The default-deny principle means that traffic is blocked unless it is explicitly allowed. The `default-deny-ingress` NetworkPolicy selects all Pods in `tenant-b` and applies an ingress policy without allowing any ingress sources. As a result, the request from `tenant-a` that previously returned HTTP 200 timed out after the policy was applied.

---

## Q3. How do virtual machines and containers differ in isolation strength? When would you add a VM boundary?

Containers share the host operating system kernel, so their isolation is primarily provided by operating-system-level mechanisms such as namespaces and control groups. Virtual machines provide a stronger isolation boundary because each VM runs its own operating system and kernel. A VM boundary may be added when tenants require stronger security isolation, when workloads are highly sensitive, or when the risk of container escape or shared-kernel vulnerabilities must be reduced.

---

## Q4. What is data remanence, and why is cryptographic erasure the preferred cloud solution?

Data remanence is the persistence of data after a file has been deleted. In cloud environments, customers generally do not control the physical storage blocks, so traditional physical overwriting cannot reliably be performed by the tenant. Cryptographic erasure is therefore practical because destroying the encryption key makes the encrypted data inaccessible even if underlying storage blocks remain.

---

## Q5. Which of the three isolation dimensions did each task exercise?

| Task | Isolation Dimension | Description |
|---|---|---|
| Task 1 | Compute | Separate tenants using Kubernetes namespaces and workloads |
| Task 2 | Network | Demonstrated that cross-tenant communication was initially allowed |
| Task 3 | Compute / Resource | Limited CPU, memory, and Pod consumption with ResourceQuota |
| Task 4 | Network | Blocked cross-tenant ingress using NetworkPolicy |
| Task 5 | Storage / Access | Protected tenant secrets using RBAC |
| Task 6 | Storage | Demonstrated data remanence and secure deletion |

---

# Security Best-Practices Checklist

- [x] Tenants are separated into distinct Kubernetes namespaces.
- [x] Default-open cross-tenant communication was demonstrated.
- [x] A ResourceQuota was applied to limit tenant resource consumption.
- [x] A default-deny NetworkPolicy was applied to block cross-tenant ingress.
- [x] Before-and-after network isolation results were captured.
- [x] Per-tenant Secrets were created.
- [x] RBAC was configured to restrict Secret access between namespaces.
- [x] Data remanence and secure deletion were demonstrated.

---

# Challenges Encountered

1. The initial Kubernetes configuration did not have a current context selected, causing `kubectl` to attempt to connect to `localhost:8080`.
2. The Lab 2 cluster had to be identified correctly as `ccse-lab2`, rather than the Lab 1 cluster.
3. The ResourceQuota required CPU and memory requests for the temporary probe Pod.
4. The initial `kubectl run` command did not support the `--requests` flag, so a Pod manifest with resource requests was used instead.
5. During Task 5, the RoleBinding initially referenced an incorrect ServiceAccount name (`appa` instead of `app-a`). The RoleBinding was corrected to use `tenant-a:app-a`.
6. The Task 4 probe successfully demonstrated the expected timeout after the NetworkPolicy was applied.

---

# Lessons Learned

- Learned how Kubernetes namespaces provide logical tenant separation.
- Understood that namespaces alone do not provide complete network isolation.
- Learned how ResourceQuota can reduce noisy-neighbour risks.
- Gained practical experience implementing Kubernetes NetworkPolicy.
- Learned how Kubernetes RBAC can restrict access to tenant-specific Secrets.
- Understood the importance of default-deny security controls.
- Learned about data remanence and secure deletion.
- Understood why cryptographic erasure is practical for cloud storage.

---

# References

1. Prof. Dr. Shahrulniza Musa. (2026). *IKB42603 Cloud Computing Security Essentials Lab Manual: Lab 2 – Secure Isolation & Multi-Tenancy*. Universiti Kuala Lumpur Malaysian Institute of Information Technology (UniKL MIIT).

2. Kubernetes. (n.d.). *Network Policies*. https://kubernetes.io/docs/concepts/services-networking/network-policies/

3. Kubernetes. (n.d.). *Role-Based Access Control (RBAC)*. https://kubernetes.io/docs/reference/access-authn-authz/rbac/

4. Calico. (n.d.). *Calico Documentation*. https://docs.tigera.io/

5. Docker. (n.d.). *Docker Documentation*. https://docs.docker.com/

---

# Conclusion

This lab successfully demonstrated the three major dimensions of secure isolation in a multi-tenant Kubernetes environment: compute/resource isolation, network isolation, and storage/access isolation. Separate namespaces were used to model different tenants, while ResourceQuota limited shared resource consumption. The default-open network behaviour was demonstrated with an HTTP 200 response, and a default-deny NetworkPolicy subsequently blocked the same cross-tenant request, producing a timeout.

RBAC was used to restrict the `app-a` ServiceAccount to Secrets within `tenant-a` while preventing access to `tenant-b`. Finally, the data remanence exercise demonstrated the limitations of normal deletion and the importance of secure deletion and cryptographic erasure in cloud environments.

Overall, the lab provided practical experience in applying Kubernetes isolation and access-control mechanisms to reduce the security risks associated with multi-tenant cloud infrastructure.
