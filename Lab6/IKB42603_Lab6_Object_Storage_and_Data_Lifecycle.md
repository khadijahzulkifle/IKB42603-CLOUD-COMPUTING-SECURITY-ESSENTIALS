# IKB42603 Cloud Computing Security Essentials

## Lab 6: Object Storage Security & the Data Security Lifecycle

**Name:** Khadijah

## 1. Objective

The objective of this lab is to understand and apply object storage
security using Amazon S3 on LocalStack.

The lab covers data classification, public bucket exposure, Block Public
Access, IAM and bucket policies, SSE-KMS encryption, presigned URLs,
versioning, data remanence, lifecycle rules, and cryptographic erasure.

## 2. Learning Outcomes

After completing this lab, I learned how to:

-   Classify data before storing it in object storage.
-   Identify and remediate a publicly readable bucket.
-   Understand identity-based and resource-based policies.
-   Apply least-privilege access to object prefixes.
-   Protect objects using default SSE-KMS encryption.
-   Use time-limited presigned URLs for delegated access.
-   Understand versioning, delete markers, and data remanence.
-   Apply lifecycle and retention rules.
-   Understand cryptographic erasure using a KMS key.

## 3. Environment

-   Kali Linux
-   Docker
-   LocalStack Pro
-   AWS CLI
-   Amazon S3 API
-   AWS KMS API
-   `curl`

## 4. Step-by-Step Implementation

### Task 1: Classify the Data Before You Store It

A bucket was created for a hospital records system. Three objects were
created with different sensitivity levels.

``` bash
export BUCKET=miit-patient-records-$RANDOM
echo $BUCKET

aws $EP s3api create-bucket --bucket $BUCKET

echo 'Ward visiting hours 10am-8pm' > public-notice.txt
echo 'Staff duty schedule, week 12' > internal-roster.txt
echo 'Patient: Ahmad bin Ali, Diagnosis: confidential' > confidential-record.txt

aws $EP s3api put-object --bucket $BUCKET --key public/notice.txt \
  --body public-notice.txt --tagging 'classification=public'

aws $EP s3api put-object --bucket $BUCKET --key internal/roster.txt \
  --body internal-roster.txt --tagging 'classification=internal'

aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body confidential-record.txt --tagging 'classification=confidential'

aws $EP s3api list-objects-v2 --bucket $BUCKET \
  --query 'Contents[].[Key,Size]' --output table

aws $EP s3api get-object-tagging --bucket $BUCKET \
  --key confidential/record.txt
```

### Data Classification Table

  -----------------------------------------------------------------------
  Classification    Who may read it   Impact if leaked  Control you will
                                                        apply
  ----------------- ----------------- ----------------- -----------------
  Public            Anyone who needs  Low               Public data only;
                    the public                          no confidential
                    information                         access

  Internal          Authorised staff  Medium            Least-privilege
                                                        access to
                                                        `internal/`

  Confidential      Authorised        High              Block public
                    personnel only                      access, least
                                                        privilege,
                                                        SSE-KMS and
                                                        lifecycle
                                                        controls
  -----------------------------------------------------------------------

### Result

The three objects were stored with classification tags: `public`,
`internal`, and `confidential`.

## Task 2: Reproduce the Archetypal Breach

A deliberately insecure bucket policy was created using
`Principal: "*"`.

``` bash
cat > public-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicReadEverything",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::$BUCKET/*"
  }]
}
JSON

aws $EP s3api put-bucket-policy \
  --bucket $BUCKET \
  --policy file://public-policy.json

aws $EP s3api get-bucket-policy \
  --bucket $BUCKET \
  --query Policy --output text

curl -s -o leaked.txt -w 'HTTP %{http_code}\n' \
  http://localhost:4566/$BUCKET/confidential/record.txt

cat leaked.txt
```

### Result

Expected result:

``` text
HTTP 200
Patient: Ahmad bin Ali, Diagnosis: confidential
```

This demonstrates the breach because an anonymous request could read the
confidential object.

The single element that caused the exposure was:

``` text
"Principal": "*"
```

## Task 3: Remediate with Block Public Access

The public policy was removed and all four Block Public Access settings
were enabled.

``` bash
aws $EP s3api delete-bucket-policy --bucket $BUCKET

aws $EP s3api put-public-access-block --bucket $BUCKET \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

aws $EP s3api get-public-access-block --bucket $BUCKET
```

The public policy was then tested again:

``` bash
aws $EP s3api put-bucket-policy \
  --bucket $BUCKET \
  --policy file://public-policy.json

curl -s -o /dev/null -w 'anonymous read now: HTTP %{http_code}\n' \
  http://localhost:4566/$BUCKET/confidential/record.txt
```

### Least-Privilege Policy

``` bash
cat > least-privilege-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AccountReadInternalOnly",
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::$BUCKET/internal/*"
  }]
}
JSON

aws $EP s3api put-bucket-policy \
  --bucket $BUCKET \
  --policy file://least-privilege-policy.json
```

### Result

All four public-access-block settings were configured as `true`.

LocalStack may store the Block Public Access configuration without fully
enforcing it. Therefore, an anonymous request may still return HTTP 200
in LocalStack. The configuration output is kept as evidence, while the
report explains the LocalStack limitation.

## Task 4: Identity Policy vs Resource Policy

An IAM user called `DataAnalyst` was created with an identity policy
that allows S3 read operations.

``` bash
aws $EP iam create-user --user-name DataAnalyst

cat > analyst-iam.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": "*"
  }]
}
JSON

aws $EP iam put-user-policy \
  --user-name DataAnalyst \
  --policy-name S3ReadAll \
  --policy-document file://analyst-iam.json

aws $EP iam create-access-key \
  --user-name DataAnalyst \
  --query 'AccessKey.[AccessKeyId,SecretAccessKey]' \
  --output text
```

The access-key values were configured in the `analyst` profile.

``` bash
ANALYST_KEY_ID='PASTE_KEY_ID_HERE'
ANALYST_SECRET='PASTE_SECRET_HERE'

aws configure --profile analyst set aws_access_key_id "$ANALYST_KEY_ID"
aws configure --profile analyst set aws_secret_access_key "$ANALYST_SECRET"
aws configure --profile analyst set region us-east-1
```

A bucket policy was created to allow internal access but explicitly deny
confidential access.

``` bash
cat > deny-confidential.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAnalystInternal",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::000000000000:user/DataAnalyst"
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::$BUCKET/internal/*"
    },
    {
      "Sid": "DenyAnalystConfidential",
      "Effect": "Deny",
      "Principal": {
        "AWS": "arn:aws:iam::000000000000:user/DataAnalyst"
      },
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::$BUCKET/confidential/*"
    }
  ]
}
JSON

aws $EP s3api put-bucket-policy \
  --bucket $BUCKET \
  --policy file://deny-confidential.json
```

### Test Internal Access

``` bash
AWS_PROFILE=analyst aws $EP s3api get-object \
  --bucket $BUCKET \
  --key internal/roster.txt \
  analyst-internal.txt && echo "internal: ALLOWED"
```

### Test Confidential Access

``` bash
AWS_PROFILE=analyst aws $EP s3api get-object \
  --bucket $BUCKET \
  --key confidential/record.txt \
  analyst-conf.txt || echo "confidential: DENIED"
```

### Result

Expected result:

``` text
internal: ALLOWED
confidential: DENIED
```

An explicit `Deny` overrides an `Allow`. Therefore, the analyst can read
the internal object but cannot read the confidential object.

Before Session B, the bucket policy was removed:

``` bash
aws $EP s3api delete-bucket-policy --bucket $BUCKET
```

## Task 5: Default Encryption at Rest (SSE-KMS)

A dedicated KMS key was created for the bucket.

``` bash
export KEY_ID=$(aws $EP kms create-key \
  --description 'IKB42603 Lab6 patient records bucket key' \
  --query 'KeyMetadata.KeyId' --output text)

echo $KEY_ID
```

The default SSE-KMS configuration was created.

``` bash
cat > encryption.json <<JSON
{
  "Rules": [{
    "ApplyServerSideEncryptionByDefault": {
      "SSEAlgorithm": "aws:kms",
      "KMSMasterKeyID": "$KEY_ID"
    },
    "BucketKeyEnabled": true
  }]
}
JSON

aws $EP s3api put-bucket-encryption --bucket $BUCKET \
  --server-side-encryption-configuration file://encryption.json

aws $EP s3api get-bucket-encryption --bucket $BUCKET
```

An object was uploaded without specifying an encryption option.

``` bash
aws $EP s3api put-object --bucket $BUCKET \
  --key confidential/record-v2.txt --body confidential-record.txt
```

The encryption status was checked:

``` bash
aws $EP s3api head-object --bucket $BUCKET \
  --key confidential/record-v2.txt \
  --query '[ServerSideEncryption,SSEKMSKeyId,BucketKeyEnabled]' \
  --output text
```

### Result

Expected result:

``` text
aws:kms    <KMS-key-ID>    True
```

This proves that the bucket automatically applied SSE-KMS encryption.

## Task 6: Delegated Access and the Condition-Key Trap

### Part A: Presigned URL

A time-limited presigned URL was created.

``` bash
aws $EP s3 presign s3://$BUCKET/internal/roster.txt --expires-in 60
```

The URL was tested:

``` bash
URL='PASTE_PRESIGNED_URL_HERE'

curl -s -w ' <-- HTTP %{http_code}\n' "$URL"
```

After 60 seconds:

``` bash
sleep 65

curl -s -o /dev/null -w 'after expiry: HTTP %{http_code}\n' "$URL"
```

### Result

The presigned URL provides access to one specific object for a limited
period without giving the recipient AWS credentials.

LocalStack may not enforce the expiry in the same way as real AWS, so an
HTTP 200 after expiry may occur.

### Part B: SecureTransport Policy

A policy was created to deny requests that do not use secure transport.

``` bash
cat > secure-transport.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyUnencryptedTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::$BUCKET",
      "arn:aws:s3:::$BUCKET/*"
    ],
    "Condition": {
      "Bool": {
        "aws:SecureTransport": "false"
      }
    }
  }]
}
JSON

aws $EP s3api put-bucket-policy \
  --bucket $BUCKET \
  --policy file://secure-transport.json

aws $EP s3api list-objects-v2 --bucket $BUCKET
```

### Result

The LocalStack endpoint uses:

``` text
http://localhost:4566
```

Therefore, the lab expects `aws:SecureTransport` to be false. However,
LocalStack may not enforce this condition and may still allow the
request.

The policy was removed before continuing:

``` bash
aws $EP s3api delete-bucket-policy --bucket $BUCKET
```

## Task 7: Versioning, Delete Markers & Data Remanence

Versioning was enabled:

``` bash
aws $EP s3api put-bucket-versioning --bucket $BUCKET \
  --versioning-configuration Status=Enabled

aws $EP s3api get-bucket-versioning --bucket $BUCKET
```

Two new versions of the confidential record were created.

``` bash
echo 'Patient: Ahmad bin Ali, Diagnosis: hypertension' > rec-v2.txt
echo 'Patient: [REDACTED], Diagnosis: [REDACTED]' > rec-v3.txt

aws $EP s3api put-object --bucket $BUCKET \
  --key confidential/record.txt \
  --body rec-v2.txt --query VersionId --output text

aws $EP s3api put-object --bucket $BUCKET \
  --key confidential/record.txt \
  --body rec-v3.txt --query VersionId --output text
```

All versions were listed:

``` bash
aws $EP s3api list-object-versions \
  --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'Versions[].[VersionId,IsLatest,Size]' \
  --output table
```

The object was deleted:

``` bash
aws $EP s3api delete-object \
  --bucket $BUCKET \
  --key confidential/record.txt
```

The delete marker was checked:

``` bash
aws $EP s3api list-object-versions \
  --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'DeleteMarkers[].[VersionId,IsLatest]' \
  --output table
```

The deleted object was then recovered using the original `null` version:

``` bash
aws $EP s3api get-object \
  --bucket $BUCKET \
  --key confidential/record.txt \
  --version-id null \
  recovered.txt

cat recovered.txt
```

### Result

The original record could still be recovered even though the object had
been deleted.

This demonstrates **object-level data remanence**. With versioning
enabled, deleting an object creates a delete marker while previous
versions remain.

## Task 8: Lifecycle, Retention & Cryptographic Erasure

### Part A: Lifecycle Configuration

``` bash
cat > lifecycle.json <<'JSON'
{
  "Rules": [
    {
      "ID": "RetireConfidentialRecords",
      "Filter": {"Prefix": "confidential/"},
      "Status": "Enabled",
      "Expiration": {"Days": 365},
      "NoncurrentVersionExpiration": {"NoncurrentDays": 30}
    },
    {
      "ID": "AbortIncompleteUploads",
      "Filter": {"Prefix": ""},
      "Status": "Enabled",
      "AbortIncompleteMultipartUpload": {
        "DaysAfterInitiation": 7
      }
    }
  ]
}
JSON

aws $EP s3api put-bucket-lifecycle-configuration \
  --bucket $BUCKET \
  --lifecycle-configuration file://lifecycle.json

aws $EP s3api get-bucket-lifecycle-configuration \
  --bucket $BUCKET \
  --query 'Rules[].[ID,Status]' --output table
```

### Result

Expected rules:

``` text
RetireConfidentialRecords    Enabled
AbortIncompleteUploads       Enabled
```

The lifecycle policy automatically manages retention.

### Part B: Cryptographic Erasure

The KMS key was checked:

``` bash
aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.[KeyId,KeyState,Enabled]' --output text
```

The key was disabled:

``` bash
aws $EP kms disable-key --key-id $KEY_ID
```

Key deletion was scheduled:

``` bash
aws $EP kms schedule-key-deletion \
  --key-id $KEY_ID \
  --pending-window-in-days 7
```

The key state was verified:

``` bash
aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.[KeyState,DeletionDate]' --output text
```

An encrypted object was tested:

``` bash
aws $EP s3api get-object \
  --bucket $BUCKET \
  --key confidential/record-v2.txt \
  after-erasure.txt
```

### Result

Expected KMS state:

``` text
PendingDeletion
```

LocalStack may still return an encrypted object after the key is
disabled because it may not re-check KMS key state during an S3 read.
The important security principle is that destruction of the encryption
key makes ciphertext unrecoverable when the key is no longer available.

## 5. Screenshots

### Task 1

Insert screenshot showing the object list and confidential
classification tag.

![alt text](<task 1.png>)

### Task 2

Insert screenshot showing the anonymous HTTP 200 response and leaked
confidential record.

![alt text](<task 2.png>)

### Task 3

Insert screenshot showing all four Block Public Access flags as `true`.

![alt text](<task 3.png>)

### Task 4

Insert screenshot showing:

``` text
internal: ALLOWED
confidential: DENIED
```

![alt text](<task 4.1.png>)
![alt text](<task 4.2.png>)
![alt text](<task 4.3.png>)

### Task 5

Insert screenshot showing `aws:kms`, the KMS key ID, and bucket key
status.

![alt text](<task 5.png>)

### Task 6

Insert screenshots showing the presigned URL test and SecureTransport
policy test.

![alt text](<task 6.png>)

### Task 7

Insert screenshots showing version listing, delete marker, and recovered
original record.

![alt text](<task 7.1.png>)
![alt text](<task 7.2.png>)

### Task 8

Insert screenshots showing lifecycle rules and KMS key state after
scheduling deletion.

![alt text](<task 8.png>)
![alt text](<task 8.1.png>)

## 6. Challenges Encountered

The main challenge was that LocalStack Pro required a valid
authentication token before it could start.

Another challenge was that some security controls, such as Block Public
Access and `aws:SecureTransport`, may not be fully enforced by
LocalStack in the same way as real AWS.

Understanding versioning was also challenging because deleting the
current object only created a delete marker while older versions
remained available.

## 7. Lessons Learned

I learned that:

-   Object storage requires careful access control because a wrong
    bucket policy can expose sensitive data.
-   `Principal: "*"` can make objects publicly readable.
-   Block Public Access provides a preventative guardrail against public
    exposure.
-   IAM policies and bucket policies both affect access, and an explicit
    Deny overrides an Allow.
-   SSE-KMS protects data at rest but does not replace access-control
    policies.
-   Presigned URLs provide temporary access without sharing AWS
    credentials.
-   Versioning means that deleting an object does not necessarily
    destroy previous versions.
-   Lifecycle rules automate data retention and deletion.
-   Cryptographic erasure can provide stronger deletion assurance when
    the encryption key is destroyed.

## 8. Short-Answer Questions

### Q1. Which single element of the Task 2 policy caused the exposure, and why is `Principal: "*"` more dangerous on a bucket policy than an over-broad IAM policy attached to one user?

**Answer:**

The element that caused the exposure was:

``` text
"Principal": "*"
```

It means any principal can access the object when the policy allows the
action. A bucket policy affects access to the resource and can therefore
expose data to many or all users, while an over-broad IAM policy
attached to one user is limited to that identity.

### Q2. Explain the difference between an identity-based policy and a resource-based policy. In Task 4, which one decided each of the analyst's two requests?

**Answer:**

An identity-based policy is attached to an IAM identity such as a user.
A resource-based policy is attached directly to a resource such as an S3
bucket.

In Task 4, the IAM policy allowed the analyst to read objects. The
bucket policy allowed access to `internal/*` but explicitly denied
access to `confidential/*`. The explicit Deny decided the confidential
request, while the combined Allow statements permitted the internal
request.

### Q3. Block Public Access is described as a guardrail rather than a control. What is the difference, and why does the distinction matter for an organisation with many engineers?

**Answer:**

A normal access control can allow or deny a particular request. A
guardrail provides a broader preventative protection that helps stop
engineers from accidentally creating unsafe configurations.

This matters in a large organisation because many engineers may create
or modify buckets. A guardrail reduces the chance that one configuration
mistake will expose sensitive data.

### Q4. Your bucket has default SSE-KMS encryption. Does that protect the confidential record from the analyst in Task 4?

**Answer:**

No. SSE-KMS protects the object while it is stored by encrypting it at
rest. It does not decide whether an analyst is authorised to access the
object. IAM and bucket policies are still required to control access.

### Q5. A patient invokes their right to erasure. Using your Task 7 evidence, explain why `delete-object` alone is not compliant, and describe two mechanisms that would make the deletion provable.

**Answer:**

With versioning enabled, `delete-object` creates a delete marker while
previous versions remain. Therefore, the original confidential record
can still be recovered.

Two mechanisms are:

1.  Delete every object version and delete marker by version ID.
2.  Use cryptographic erasure by destroying or permanently disabling the
    encryption key that protects the data.

### Q6. You are the auditor in Week 11. Name three commands from this lab whose output you would collect as compliance evidence, and state which control each one evidences.

**Answer:**

  ---------------------------------------------------------------------------------------------------------
  Command                                                               Evidence
  --------------------------------------------------------------------- -----------------------------------
  `aws $EP s3api get-public-access-block --bucket $BUCKET`              Block Public Access configuration

  `aws $EP s3api get-bucket-encryption --bucket $BUCKET`                Default SSE-KMS encryption

  `aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET`   Retention and lifecycle controls
  ---------------------------------------------------------------------------------------------------------

## 9. Security Best-Practices Checklist

-   [x] Every object has a classification tag.
-   [x] Public access was deliberately tested and remediated.
-   [x] Block Public Access was enabled with all four flags.
-   [x] Least-privilege access was scoped to a key prefix.
-   [x] Default encryption uses SSE-KMS.
-   [x] Presigned URLs provide time-bounded access.
-   [x] Versioning is enabled.
-   [x] Delete markers and data remanence were demonstrated.
-   [x] Lifecycle rules express the retention policy.
-   [x] Cryptographic erasure was demonstrated at the KMS layer.

## 10. Verification Command

### Verify Final Security Posture

``` bash
echo "=== IKB42603 Lab 6 verification: $BUCKET ==="

aws $EP s3api get-public-access-block --bucket $BUCKET \
  --query 'PublicAccessBlockConfiguration' --output text

aws $EP s3api get-bucket-versioning --bucket $BUCKET --output text

aws $EP s3api get-bucket-encryption --bucket $BUCKET \
  --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.[SSEAlgorithm,KMSMasterKeyID]' \
  --output text

aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET \
  --query 'Rules[].[ID,Status]' --output text

aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.KeyState' --output text
```

### Result

The verification output should show:

``` text
Block Public Access: all four settings enabled
Versioning: Enabled
Encryption: aws:kms
Lifecycle: Enabled rules
KMS Key State: PendingDeletion
```

![alt text](<verification command.png>)

## 11. References

1.  **IKB42603 Cloud Computing Security Essentials Lab Manual** --- Lab
    6: Object Storage Security & the Data Security Lifecycle.
2.  Amazon S3 Security Best Practices.
3.  Amazon S3 Versioning and Lifecycle Documentation.
4.  LocalStack S3 Coverage and Limitations.
5.  Cloud Security Alliance Security Guidance v5.
6.  MCMC MTSFB TC G017:2021 --- Information Security Requirements for
    Cloud Service Providers.
