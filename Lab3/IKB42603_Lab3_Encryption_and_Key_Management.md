# Lab 3: Encryption and Key Management

**Course:** IKB42603 Cloud Computing Security Essentials  
**Lab:** Lab 3  
**Topic:** Data Protection & Key Management  
**Environment:** Kali Linux, Docker, OpenSSL, AWS CLI, LocalStack KMS  
**Name:** Khadijah

---

## Objective

To demonstrate data protection techniques using encryption and key management, including AES symmetric encryption, RSA asymmetric encryption and digital signatures, TLS encryption in transit, KMS, envelope encryption, per-tenant keys, cryptographic erasure, hashing, and hash-chained integrity verification.

## Learning Outcomes

At the end of this lab, you will be able to:

1. Encrypt and decrypt data using symmetric AES and asymmetric RSA cryptography.
2. Protect data in transit using TLS.
3. Use a Key Management Service (KMS) and implement envelope encryption.
4. Apply per-tenant keys and demonstrate cryptographic erasure.
5. Verify data integrity using SHA-256 hashing and a hash chain.

## Environment

- Operating system: Kali Linux / Linux terminal
- OpenSSL
- Docker
- AWS CLI v2
- LocalStack
- LocalStack KMS endpoint: `http://localhost:4566`

## Step-by-Step Implementation

This lab is divided into two sessions:

### Session A — Week 5

- Task 1: Symmetric Encryption (AES-256)
- Task 2: Asymmetric Encryption & Digital Signatures (RSA)
- Task 3: Encryption in Transit (TLS)

### Session B — Week 6

- Task 4: Create and Use a KMS Master Key
- Task 5: Envelope Encryption
- Task 6: Per-Tenant Keys & Cryptographic Erasure
- Task 7: Integrity & Tamper-Evidence

Detailed commands and procedures are provided in the sections below.

## Commands Used

The main tools and commands used in this lab include:

- `openssl enc`
- `openssl genrsa`
- `openssl rsa`
- `openssl pkeyutl`
- `openssl dgst`
- `openssl req`
- `curl`
- `docker run`
- `docker stop`
- `aws kms create-key`
- `aws kms encrypt`
- `aws kms generate-data-key`
- `aws kms schedule-key-deletion`
- `aws kms disable-key`
- `aws kms decrypt`
- `sha256sum`

## Screenshots

Include screenshots as evidence for the following:

- Task 1: AES encryption/decryption and `MATCH: decryption successful`
- Task 2: RSA signature verification showing `Verified OK`
- Task 3: HTTPS/TLS connection using `curl -k`
- Task 4: KMS master key creation and KeyId
- Task 5: Envelope encryption and removal of the plaintext data key
- Task 6: Failed KMS decrypt after key erasure
- Task 7: Different SHA-256 hashes and the hash chain

## Challenges Encountered

Record any problems encountered during the lab, such as:

- OpenSSL command errors
- Docker or container errors
- LocalStack connection problems
- AWS CLI/KMS configuration errors
- Incorrect file paths or missing files
- Encryption or decryption failures

For each challenge, describe the error and the solution used.

## Lessons Learned

The lab demonstrates that encryption alone is not sufficient for cloud data protection. Secure key management is essential. Symmetric encryption is efficient but requires secure key distribution, while asymmetric cryptography supports secure key exchange and digital signatures. TLS protects data in transit, KMS supports centralized key management, envelope encryption protects large amounts of data efficiently, and cryptographic erasure can make encrypted data unrecoverable when its protecting key is disabled or deleted. Hashing provides integrity verification and hash chains make changes to a sequence of records detectable.


## Lab Learning Outcomes

At the end of this lab, you will be able to:

1.  Encrypt and decrypt data with symmetric (AES) and asymmetric (RSA)
    cryptography.
2.  Protect data in transit with TLS and observe the difference between
    plaintext and encrypted traffic.
3.  Use a Key Management Service (KMS) and implement envelope
    encryption.
4.  Apply per-tenant keys and perform cryptographic erasure to make data
    provably unrecoverable.
5.  Verify data integrity with hashing and build a tamper-evident
    (hash-chained) record.

------------------------------------------------------------------------

## Session A (Week 5) --- Encryption Fundamentals

### Task 1 --- Symmetric Encryption (Data at Rest)

Create a sensitive file and encrypt it with AES-256. Then decrypt it.
One shared key does both --- fast, but the key must be protected.

``` bash
# Create a sample sensitive record
echo 'Patient: Ahmad, Diagnosis: confidential' > record.txt

# Encrypt with AES-256 (you will be prompted for a passphrase = the key)
openssl enc -aes-256-cbc -pbkdf2 -salt -in record.txt -out record.enc

# Prove it is unreadable
cat record.enc

# Decrypt back
openssl enc -d -aes-256-cbc -pbkdf2 -in record.enc -out record.dec.txt

diff record.txt record.dec.txt && echo 'MATCH: decryption successful'
```
![alt text](<task 1.png>)

**In your report:** What is the key-distribution problem with symmetric
encryption, and why does it matter for the cloud?

### Task 2 --- Asymmetric Encryption & Digital Signatures

Generate an RSA key pair. Anyone can encrypt with the public key; only
the private key decrypts. Signatures prove origin and integrity.

``` bash
# Generate a 2048-bit key pair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Encrypt with the PUBLIC key, decrypt with the PRIVATE key
openssl pkeyutl -encrypt -pubin -inkey public.pem -in record.txt -out record.rsa
openssl pkeyutl -decrypt -inkey private.pem -in record.rsa -out record.rsa.txt

# Sign with the PRIVATE key; verify with the PUBLIC key
openssl dgst -sha256 -sign private.pem -out record.sig record.txt
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
```
![alt text](<task 2.png>)

> **Note:** Note how the roles reverse: encryption uses the public key,
> signing uses the private key. This is the basis of PKI and TLS.

### Task 3 --- Encryption in Transit (TLS)

Serve a file over HTTPS with a self-signed certificate and confirm the
channel is encrypted.

``` bash
# Generate a self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 7 -nodes -subj '/CN=localhost'

# Serve HTTPS on port 8443 using a small container
docker run --rm -d --name tls -p 8443:443 -v $(pwd)/cert.pem:/etc/nginx/cert.pem -v $(pwd)/key.pem:/etc/nginx/key.pem -v $(pwd)/record.txt:/usr/share/nginx/html/record.txt nginx

# Connect over TLS (-k accepts the self-signed cert)
curl -k https://localhost:8443/record.txt
```
![alt text](<task 3.png>)

**Security tip:** Compare mentally with plain HTTP: over HTTP the record
would travel in clear text and any on-path attacker could read it
(eavesdropping, Week 3). TLS makes intercepted traffic unreadable.

**End of Session A:** Stop the TLS container:

``` bash
docker stop tls
```

Keep `record.enc`, the RSA keys, and all outputs for the report.

------------------------------------------------------------------------

## Session B (Week 6) --- Key Management, Envelope Encryption & Erasure

Start LocalStack if it is not running (see Lab 1). Set:

``` bash
EP='--endpoint-url=http://localhost:4566'
```

### Task 4 --- Create and Use a KMS Master Key

``` bash
EP='--endpoint-url=http://localhost:4566'

# Create a customer master key (CMK) and capture its KeyId
aws $EP kms create-key --description 'CCSE tenant-A master key'

# Copy the KeyId from the output into KEY_A below
KEY_A=<PASTE_KEYID>

# Encrypt a small secret directly with KMS
aws $EP kms encrypt --key-id $KEY_A --plaintext "$(echo -n 'hello' | base64)" --query CiphertextBlob --output text
```
![alt text](<Task 4.png>)

### Task 5 --- Envelope Encryption

For large data you do not encrypt with the master key directly. You
generate a data key, encrypt the data with it locally, and store the
data key wrapped by the master key. This is envelope encryption.

#### 5.1 Ask KMS for a data key

``` bash
aws $EP kms generate-data-key --key-id $KEY_A --key-spec AES_256 --query '[Plaintext,CiphertextBlob]' --output text
```

Save column 1 as `datakey.b64` (plaintext) and column 2 as `datakey.enc`
(wrapped).

![alt text](<task 5.1.png>)

#### 5.2 Encrypt the big file locally with the plaintext data key

``` bash
base64 -d datakey.b64 > datakey.bin

openssl enc -aes-256-cbc -pbkdf2 -in record.txt -out record.env.enc -pass file:./datakey.bin
```
![alt text](<task 5.2.png>)

#### 5.3 Destroy the plaintext data key from disk

``` bash
rm datakey.bin datakey.b64
echo 'Only the KMS-wrapped data key (datakey.enc) remains.'
```

> **Note:** To read the data later you send `datakey.enc` back to KMS
> (`kms decrypt`) to unwrap it, use it, then discard it. Only the small
> master key ever needs hardware-grade protection.

![alt text](<task 5.3.png>)

### Task 6 --- Per-Tenant Keys & Cryptographic Erasure

Create a second tenant key and show that one tenant's key cannot read
another's data. Then delete a key to make its data permanently
unrecoverable --- cryptographic erasure.

``` bash
# A separate key for tenant B
aws $EP kms create-key --description 'CCSE tenant-B master key'
KEY_B=<PASTE_KEYID>

# Schedule deletion of tenant A's key (min window)
aws $EP kms schedule-key-deletion --key-id $KEY_A --pending-window-in-days 7

# Disable it immediately to simulate erasure
aws $EP kms disable-key --key-id $KEY_A

# Attempt to unwrap tenant A's data key now — it should FAIL
aws $EP kms decrypt --ciphertext-blob fileb://datakey.enc 2>&1 | head -3
```

> **Caution:** Once the key that wrapped the data key is gone,
> `record.env.enc` is just noise --- no one, not even the provider, can
> decrypt it. This is why per-object/per-tenant keys make deletion
> provable.

![alt text](<task 6.1.png>)
![alt text](<task 6.2.png>)

### Task 7 --- Integrity & Tamper-Evidence

Encryption protects confidentiality; hashing protects integrity. Detect
tampering and build a simple hash chain.

``` bash
# Fingerprint the file
sha256sum record.txt

# Tamper with a copy and show the hash changes
cp record.txt tampered.txt; echo 'x' >> tampered.txt
sha256sum record.txt tampered.txt

# Hash chain: each entry includes the previous hash (tamper-evident log)
PREV=0
for line in 'login ok' 'file read' 'export data'; do   PREV=$(echo -n "$PREV$line" | sha256sum | cut -d' ' -f1);   echo "$line | $PREV"; done
```
![alt text](<task 7.png>)
------------------------------------------------------------------------

# Deliverables & Assessment

## 1. Evidence

Label each clearly:

-   AES encrypt/decrypt with the `MATCH` confirmation (Task 1).
-   RSA signature verify output showing `Verified OK` (Task 2).
-   The `curl -k https://…` output over TLS (Task 3).
-   The KMS KeyId(s) and the envelope-encryption steps (Tasks 4--5).
-   The failed KMS decrypt after key erasure (Task 6).
-   The two differing SHA-256 hashes and the hash chain (Task 7).

## 2. Short-Answer Questions

### Q1. Compare symmetric and asymmetric encryption:

Symmetric encryption uses one key to encrypt and decrypt data. It is fast and suitable for large cloud data. Asymmetric encryption uses a public key and private key. It is slower but useful for secure key exchange and digital signatures.

### Q2. Why is key management described as the weakest link, not the algorithm?

Because even strong encryption can be unsafe if the encryption keys are stolen, lost, or poorly protected. In cloud security, keys must be securely stored, controlled, and managed.

### Q3. Explain envelope encryption and why only the master key needs hardware-grade protection.

Envelope encryption uses a data key to encrypt the data and a master key to protect the data key. This is secure for cloud storage because the master key is kept highly protected, while the data key is used for the actual encryption.

### Q4. How does cryptographic erasure achieve provable deletion where overwriting cannot (in the cloud)?

Cryptographic erasure deletes or disables the encryption key used to protect the data. Without the key, the encrypted cloud data cannot be decrypted, even if copies or backups still exist.

### Q5. How does a hash chain make a log tamper-evident (link to tamper-proof logs, Week 6)?

A hash chain links each log entry to the hash of the previous entry. If someone changes a log entry, the hash changes and the modification can be detected. This helps protect the integrity of cloud security logs.


## Security Best-Practices Checklist

-   [x] Data encrypted at rest (AES) and decryption verified.
-   [x] Asymmetric keys used correctly (encrypt with public, sign with
    private).
-   [x] Data protected in transit with TLS.
-   [x] Envelope encryption used; plaintext data key not left on disk.
-   [x] Per-tenant keys used; cryptographic erasure demonstrated.
-   [x] Integrity verified with hashing / hash chain.

## Expansion Ideas (Advanced Students)

-   Store the master key in a software HSM (SoftHSM) and use PKCS#11 to
    sign --- model hardware key protection.
-   Stand up HashiCorp Vault in a container and use its transit engine
    for envelope encryption.
-   Configure mutual TLS (mTLS) between two containers so both sides
    authenticate.
-   Automate key rotation and re-wrap existing data keys under a new
    master key.

## References

-   IKB42603 Cloud Computing Security Essentials. Lab 3: Data Protection: Encryption & Key Management. UniKL MIIT, Prof. Dr. Shahrulniza Musa.
-   OpenSSL documentation --- www.openssl.org/docs
-   CSA Security Guidance v5 --- Data Security & Encryption.
