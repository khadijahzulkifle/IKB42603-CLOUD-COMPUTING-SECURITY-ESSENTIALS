# IKB42603 Cloud Computing Security Essentials
## Lab 4: Access Control & Network Security
**Name:** Khadijah  

## 1. Objective

The objective of this lab is to understand and apply access control and network security using Docker and Kubernetes.

The lab covers authentication, MFA, RBAC, network segmentation, firewall rules, and container hardening.

## 2. Learning Outcomes

After completing this lab, I learned how to:

- Implement authentication.
- Implement MFA using TOTP.
- Apply authorization using Kubernetes RBAC.
- Configure network segmentation.
- Configure default-deny firewall rules.
- Harden a container using security controls.

## 3. Environment

- Kali Linux
- Docker
- Kubernetes
- kubectl
- Kind
- Nginx
- Redis
- Alpine Linux
- oathtool
- Trivy

## 4. Step-by-Step Implementation

### Task 1: Authentication

A password-protected Nginx service was created.

The service returned **401** without credentials and **200** with valid credentials.

### Task 2: MFA

A TOTP secret and 6-digit code were generated using `oathtool`.

Result:

```text
MFA OK
```

### Task 3: RBAC

A Kubernetes namespace, ServiceAccount, Role and RoleBinding were created.

The developer account could list pods but could not create deployments or delete pods.

Results:

```text
list pods       → yes
create deploy   → no
delete pods     → no
```

### Task 4: Network Segmentation

Three tiers were separated using Docker networks:

- Web
- Application
- Database

Results:

```text
web → db = BLOCKED
app → db = REACHABLE
```

This shows that the web tier cannot directly access the database.

### Task 5: Firewall Rules

A default-deny firewall was configured using `iptables`.

The firewall allowed HTTPS traffic on port 443 and loopback traffic.

Result:

```text
Chain INPUT (policy DROP)
ACCEPT tcp ... tcp dpt:443
ACCEPT all ...
```

### Task 6: Container Hardening

The container was hardened using:

- Non-root user
- Read-only filesystem
- Dropped Linux capabilities
- No-new-privileges

A Trivy scan was also performed.

## 5. Commands Used

### Task 1

```bash
docker run --rm httpd:alpine htpasswd -nbB student 'P@ssw0rd!' > htpasswd.txt
```

```bash
curl -s -o /dev/null -w 'no-creds: %{http_code}\n' http://localhost:8080
```

```bash
curl -s -u student:'P@ssw0rd!' http://localhost:8080
```

### Task 2

```bash
SECRET=$(head -c20 /dev/urandom | base32)
oathtool --totp -b "$SECRET"
```

### Task 3

```bash
kind create cluster --name ccse-lab4
kubectl create namespace app
kubectl create serviceaccount dev -n app
kubectl create role dev-role -n app --verb=get,list --resource=pods
kubectl create rolebinding dev-rb -n app --role=dev-role --serviceaccount=app:dev
```

```bash
SA=system:serviceaccount:app:dev
kubectl auth can-i list pods -n app --as=$SA
kubectl auth can-i create deploy -n app --as=$SA
kubectl auth can-i delete pods -n app --as=$SA
```

### Task 4

```bash
docker network create frontend-net
docker network create backend-net
```

### Task 5

```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c '\
apk add -q iptables; \
iptables -P INPUT DROP; \
iptables -A INPUT -p tcp --dport 443 -j ACCEPT; \
iptables -A INPUT -i lo -j ACCEPT; \
iptables -L INPUT -n'
```

### Task 6

```bash
docker run -d --name hardened \
--user 1000:1000 \
--read-only \
--cap-drop=ALL \
--security-opt no-new-privileges \
--tmpfs /tmp \
nginxinc/nginx-unprivileged
```

```bash
docker inspect hardened --format 'User={{.Config.User}} ReadOnly={{.HostConfig.ReadonlyRootfs}}'
```

```bash
docker run --rm aquasec/trivy image --severity HIGH,CRITICAL nginx:alpine | head -20
```

## 6. Screenshots

### Task 1
Insert screenshot showing the **401** and **200** results.

![alt text](<task 1.png>)

### Task 2
Insert screenshot showing **MFA OK**.

![alt text](<TASK 2.png>)

### Task 3
Insert screenshot showing the three `kubectl auth can-i` results.

![alt text](<task 3.png>)

### Task 4
Insert screenshot showing:

```text
web → db = BLOCKED
app → db = REACHABLE
```
![alt text](<task 4.png>)

### Task 5
Insert screenshot showing:

```text
Chain INPUT (policy DROP)
ACCEPT tcp ... tcp dpt:443
```
![alt text](<task 5.png>)

### Task 6
Insert screenshots showing the hardened container inspect result and Trivy scan result.

![alt text](<task 6.png>)
![alt text](<task 6.1.png>)
![alt text](<task 6.2.png>)


## 7. Challenges Encountered

The main challenge was creating the `ccse-lab4` Kind cluster. The cluster stopped at **Starting control-plane**.

The error showed that the Kubernetes API server, scheduler and controller manager were not becoming healthy.

Some Kubernetes commands also returned **AlreadyExists** because resources such as the `app` namespace, `dev` ServiceAccount and `dev-role` had already been created.

## 8. Lessons Learned

I learned that:

- Authentication checks **who you are**.
- Authorization checks **what you can do**.
- MFA provides an additional security factor.
- RBAC applies least privilege.
- Network segmentation controls communication between services.
- Default-deny firewall rules block unwanted traffic.
- Container hardening reduces the attack surface.

## 9. Question and Answer

Q1. Explain the difference between authentication and authorization using Tasks 1 and 3.

Answer:
- Authentication checks who you are. In Task 1, the user must provide the correct username and password.
- Authorization checks what you are allowed to do. In Task 3, the dev user can list pods but cannot create deployments or delete pods.

Q2. Why is MFA so effective, and which attacks does it defeat?

Answer:
MFA adds a second factor in addition to a password. Even if an attacker gets the password, they still need the TOTP code. It helps defeat many credential attacks.

Q3. How does network segmentation limit the damage of a compromised web server?

Answer:
Network segmentation separates the web, application, and database networks. If the web server is compromised, the attacker cannot directly reach the database. This limits lateral movement and reduces the damage.

Q4. What does a default-deny firewall policy achieve, and how does it relate to cloud security groups?

Answer:
A default-deny firewall blocks traffic unless it is specifically allowed. In this task, HTTPS port 443 is allowed. This is similar to cloud security groups because only the required network traffic is permitted.

Q5. List the hardening measures you applied and the attack surface each one removes.

Answer:
- Non-root user → reduces the risk of attackers getting root privileges.
- Read-only filesystem → prevents unauthorized changes to the container.
- Drop all capabilities → removes unnecessary privileges.
- No-new-privileges → prevents gaining additional privileges.

---

## 10. Verification Command

### Container Capability Verification

```bash
docker inspect hardened --format '{{json .HostConfig.CapDrop}}'
```
![alt text](<verification command.png>)

This command verifies that Linux capabilities were dropped from the hardened container.

---

## 11. References

1. **IKB42603 Cloud Computing Security Essentials Lab Manual** — Lab 4: Access Control & Network Security, UniKL MIIT, Prof. Dr. Shahrulniza Musa.  
   Course lab manual provided by the lecturer.

2. **Docker Documentation — Docker Engine Security**  
   https://docs.docker.com/engine/security/

3. **Cloud Security Alliance (CSA) — Security Guidance v5**  
   https://cloudsecurityalliance.org/artifacts/security-guidance-v5