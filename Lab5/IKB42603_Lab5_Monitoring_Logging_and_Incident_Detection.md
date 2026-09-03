# IKB42603 Cloud Computing Security Essentials
## Lab 5: Monitoring, Logging & Incident Detection
**Name:** Khadijah

## 1. Objective

The objective of this lab is to understand and apply monitoring, logging, and incident detection using Docker and LocalStack.

The lab covers log generation, centralised logging, security monitoring, tamper-proof logs, incident detection, and incident response.

## 2. Learning Outcomes

After completing this lab, I learned how to:

- Collect and centralise logs.
- Find security-related activities such as failed logins.
- Protect logs using a hash chain.
- Detect an incident by combining different events.
- Perform incident response by containing the attacker and collecting evidence.

## 3. Environment

- Windows / Git Bash / WSL
- Docker
- LocalStack
- AWS CLI
- CloudWatch Logs
- `grep`
- `awk`
- `sha256sum`
- `iptables`

## 4. Step-by-Step Implementation

### Task 1: Generate Application Logs

An authentication log was created containing successful logins, failed login attempts, and a data export.

```bash
cat > auth.log <<'EOF'
2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5
2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9
2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB
EOF
```

Result:

```text
4 LOGIN_FAIL
1 LOGIN_OK
1 EXPORT_DATA
```

### Task 2: Centralise Logs

The logs were sent to LocalStack CloudWatch Logs.

```bash
EP='--endpoint-url=http://localhost:4566'

aws $EP logs create-log-group --log-group-name /ccse/app
aws $EP logs create-log-stream --log-group-name /ccse/app --log-stream-name auth
```

The logs were then uploaded and read back from the centralised log store.

Result:

```text
Centralised logs displayed successfully
```

### Task 3: Query Security Activity

Failed login attempts were searched and grouped by IP address.

```bash
grep LOGIN_FAIL auth.log | awk '{print $4, $5}' | sort | uniq -c
```

Result:

```text
4 failed logins from 203.0.113.9
```

This shows a possible brute-force login attempt.

### Task 4: Tamper-Proof Logs

A hash chain was created using SHA-256.

```bash
PREV=0

while IFS= read -r line; do
  PREV=$(printf '%s%s' "$PREV" "$line" | sha256sum | cut -d' ' -f1)
  printf '%s | %s\n' "$line" "$PREV"
done < auth.log > auth.chain
```

The log was then changed to simulate tampering.

```bash
sed 's/500MB/5MB/' auth.log > auth.tampered
```

Result:

```text
Original final hash ≠ Tampered final hash
```

This shows that the log was changed.

### Task 5: Detect the Incident

The suspicious IP address was checked for failed logins, successful login, and data export.

```bash
IP=203.0.113.9

FAILS=$(grep -c "LOGIN_FAIL.*$IP" auth.log)
SUCCESS=$(grep -c "LOGIN_OK.*$IP" auth.log)
EXPORT=$(grep -c "EXPORT_DATA.*$IP" auth.log)

echo "IP=$IP fails=$FAILS success=$SUCCESS export=$EXPORT"
```

The alert was generated using:

```bash
if [ "$FAILS" -ge 3 ] && [ "$SUCCESS" -ge 1 ] && [ "$EXPORT" -ge 1 ]; then
  echo 'ALERT: probable brute-force -> compromise -> data exfiltration'
fi
```

Result:

```text
ALERT: probable brute-force -> compromise -> data exfiltration
```

### Task 6: Incident Response

The suspicious IP address was blocked.

```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c 'apk add -q iptables; iptables -A INPUT -s 203.0.113.9 -j DROP; iptables -L INPUT -n | tail -2'
```

An evidence copy was created:

```bash
cp auth.log evidence_$(date +%Y%m%d).log
```

The evidence was hashed:

```bash
sha256sum evidence_*.log > evidence.sha256
```

Result:

```text
Attacker IP blocked
Evidence collected
Evidence hash created
```

## 5. Commands Used

### Task 1

```bash
cat auth.log
```

### Task 2

```bash
EP='--endpoint-url=http://localhost:4566'
aws $EP logs create-log-group --log-group-name /ccse/app
aws $EP logs create-log-stream --log-group-name /ccse/app --log-stream-name auth
aws $EP logs get-log-events --log-group-name /ccse/app --log-stream-name auth
```

### Task 3

```bash
grep LOGIN_FAIL auth.log | awk '{print $4, $5}' | sort | uniq -c
```

### Task 4

```bash
sha256sum
sed 's/500MB/5MB/' auth.log > auth.tampered
```

### Task 5

```bash
grep -c "LOGIN_FAIL.*$IP" auth.log
grep -c "LOGIN_OK.*$IP" auth.log
grep -c "EXPORT_DATA.*$IP" auth.log
```

### Task 6

```bash
iptables -A INPUT -s 203.0.113.9 -j DROP
cp auth.log evidence_$(date +%Y%m%d).log
sha256sum evidence_*.log > evidence.sha256
```

## 6. Screenshots

### Task 1

Insert screenshot showing the generated `auth.log`.

![alt text](<task 1.png>)

### Task 2

Insert screenshot showing the centralised log output.

![alt text](<task 2.png>)

### Task 3

Insert screenshot showing the failed-login count.

![alt text](<task 3.png>)

### Task 4

Insert screenshot showing the hash chain and tampering result.

![alt text](<task 4.png>)

### Task 5

Insert screenshot showing the incident alert.

![alt text](<task 5.png>)

### Task 6

Insert screenshot showing the containment rule and evidence hash.

![alt text](<task 6.png>)

## 7. Challenges Encountered

The main challenge was making sure the logs were correctly sent to LocalStack and could be read back from the centralised log store.

Another challenge was understanding the hash-chain verification. Changing one value in the log caused the final hash to become different.

## 8. Lessons Learned

I learned that:

- Logs record activities that happen in a system.
- Centralised logging makes security monitoring easier.
- Failed login attempts can show a possible attack.
- Hash chains can detect changes to logs.
- Correlation can identify an incident from several activities.
- Incident response includes detection, containment, evidence collection, and documentation.

## 9. Short-Answer Questions

## Q1. What is the difference between a log and an event?

**Answer:**

A log is a record of something that happened. For example, `LOGIN_FAIL` is a log entry.

An event can be used to trigger an alert. For example, four failed logins from the same IP can create a security alert.

## Q2. Why must audit logs be tamper-proof?

**Answer:**

Audit logs must be protected so an attacker cannot secretly change the evidence. A hash chain helps detect changes because changing a log entry changes the hash.

## Q3. How did correlation detect the incident?

**Answer:**

The system connected several activities from the same IP:

```text
4 failed logins
      ↓
Successful login
      ↓
500MB data export
      ↓
Security alert
```

Together, these activities showed a possible brute-force attack followed by compromise and data exfiltration.

## Q4. List the incident-response steps performed.

**Answer:**

- **Detect** → Find the suspicious activity.
- **Contain** → Block the attacker IP.
- **Collect evidence** → Save a copy of the log.
- **Protect evidence** → Create a SHA-256 hash.
- **Document** → Record what happened.

## Q5. How can logs be used for security and compliance?

**Answer:**

Logs can be used to monitor suspicious activities and investigate incidents. They can also be used as evidence to show what happened in the system.

## Security Best-Practices Checklist

- [x] Logs are centralised.
- [x] Failed login activity can be queried.
- [x] Logs are tamper-evident using a hash chain.
- [x] Multiple events are correlated to detect an incident.
- [x] The attacker is contained.
- [x] Evidence is collected and hashed.
- [x] The incident is documented.

## 10. Verification Command

### Verify Log Groups

```bash
aws --endpoint-url=http://localhost:4566 logs describe-log-groups
```

### Verify Evidence

```bash
sha256sum -c evidence.sha256
```

Result:

```text
evidence_*.log: OK
```
![alt text](<verficatipn commad.png>)

## 11. References

1. **IKB42603 Cloud Computing Security Essentials Lab Manual** — Lab 5: Monitoring, Logging & Incident Detection.
2. Week 6 Lecture — Monitoring, Auditing & Management.
3. Amazon CloudWatch Logs.
4. OWASP Logging Cheat Sheet.
5. Cloud Security Alliance Security Guidance v5.
