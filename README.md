# week4-workload-security

## Objective

This lab focuses on detecting suspicious AWS API enumeration activity
in CloudTrail logs.

We simulate a credential compromise scenario where the IAM user `bob`
is assumed to be compromised and used to perform automated reconnaissance.

The goal is not to perform offensive cloud operations, but to understand:

- How automated AWS reconnaissance appears in CloudTrail
- How to identify high-volume `List*`, `Get*`, `Describe*` activity
- How to correlate events over short time windows
- How to detect AccessDenied spikes during capability probing

## Intentionally Not Included

This lab deliberately excludes:

- Automated detection pipelines
- SIEM integration
- EDR tooling
- Real-time alerting systems

The purpose is to focus on understanding raw CloudTrail behavioral patterns  

## Scenario

In this lab environment, the deployed infrastructure consists of a Virtual Private Cloud (VPC) that serves as the foundational network layer for all resources. Within this VPC, there are subnets, route tables, security groups, and EC2 instances configured to simulate a typical cloud workload. The setup includes public-facing components, such as an EC2 instance accessible via SSH and HTTP, and S3 buckets for application data and CloudTrail logs. Security groups define the allowed inbound and outbound traffic, while IAM roles and policies manage user and service permissions. 

We assume that the IAM user `bob` has been compromised.

An attacker now uses automated tooling (AWS CLI / boto3-based script)
to perform capability discovery across the AWS account.

The activity simulates:
- Systematic cross-service enumeration
- Permission probing
- Privilege escalation discovery attempts

Rather than modeling attacker movement, the lab focuses on mapping observable behaviors to detection signals. This approach enables defenders to recognize early-stage cloud reconnaissance and design effective monitoring strategies before escalation or lateral movement occurs.


### Lab Preparation Steps
1. Prepare your AWS account and credentials (`aws configure`).
2. Generate or use an existing SSH key pair for EC2 access.
3. Edit `terraform/defaults.tfvars` with your AMI ID, region, instance type, and SSH key paths.
4. Initialize and apply Terraform:
   ```sh
   cd terraform
   terraform init
   terraform plan -var-file=terraform/defaults.tfvars
   terraform apply -var-file=terraform/defaults.tfvars
   ```
5. Copy the `ansible_inventory` output from Terraform to `ansible/hosts`.
6. Run the Ansible playbook on ansible folder, check details on ./ansible/README.md
7. Cleanup project:
   ```sh
   terraform destroy -var-file defaults.tfvars
   ```
Enum execution phase (generating fake Recon traffic):

1. Configure and run the script
```sh
cd ./config
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 ./recon.py
```
2. Check the cloudtrail bucket name on `./terraform/terraform.tfstate`
3. Wait some minutes and download cloudtrail logs:
```sh
mkdir ./cloudtrail-logs
aws s3 sync s3://YOUR_AWS_RESOURCE_NAME/AWSLogs/
```

## Detection Logic

The detection strategy is based on four behavioral signals:

### 1. High-Volume Read-Only API Calls
The `recon.py` script simulates an AWS enumeration phase performed by a low-privileged IAM user (`bob`) using automated SDK/API calls. In an AWS environment, enumeration does not involve traditional network scanning but API-driven enumeration of cloud resources. The script performs an unusual density of `List*`, `Get*`, and `Describe*` operations across services such as IAM, EC2, S3, Lambda, dynamodb to map the account structure, VPC topology, security groups, IAM roles, and attached policies.

### 2. Time Correlation
Multiple services enumerated within seconds or within the same minute. To detect this behavior, CloudTrail log hunting focuses on timing correlation. A refinement to improve the highlighting on time and scan correlation is the following jq filter. This visualization is to filter per minutes (`.eventTime[0:16]`), group per minutes and sort it. 

``` bash
jq -r '
  .Records[] |
  select(
    (.eventName? // "" | test("^(Get|List|Describe)")) and
    (.userAgent? // "" | test("aws-cli|boto|botocore|Boto3"))
  ) |
  [
    (.eventTime[0:16]),   # YYYY-MM-DDTHH:MM
    .userIdentity.arn
  ] |
  @tsv
' *.json | sort | uniq -c | sort -nr

     24 2026-02-11T17:00	arn:aws:iam::137809406849:user/bob
     11 2026-02-11T15:22	arn:aws:iam::137809406849:user/bob
      3 2026-02-11T15:21	arn:aws:iam::137809406849:user/bob
      1 2026-02-11T15:47	arn:aws:iam::137809406849:user/bob

```

### 3. Cross-Service Sweep
Rapid enumeration across EC2, S3, IAM, Lambda, DynamoDB. To detect this behavior, CloudTrail log hunting focuses on identifying enumeration patterns, cross-service sweeps, and burst activity within short time windows. Using `jq`, it is possible to filter CloudTrail records for a specific principal and isolate `Get|List|Describe` events, correlating them by timestamp and service. This enables detection of automated reconnaissance, especially when combined with user agent analysis (e.g., `aws-cli`, `boto3`, `botocore`) and minute-level aggregation to highlight high-density API activity.

``` bash
jq -r '                       
  .Records[] |
  select(
    (.userIdentity.userName? == "bob") and
    (.eventName? and (.eventName | test("^(Get|List|Describe)")))
  ) |
  [.eventTime, .eventSource, .eventName] |
  @tsv
' *.json

2026-02-11T15:21:57Z	ec2.amazonaws.com	DescribeSecurityGroups
2026-02-11T15:21:57Z	ec2.amazonaws.com	DescribeNetworkAcls
2026-02-11T15:21:56Z	ec2.amazonaws.com	DescribeVpcs
2026-02-11T15:22:02Z	s3.amazonaws.com	ListBuckets
2026-02-11T15:22:10Z	s3.amazonaws.com	GetBucketAcl
2026-02-11T15:22:12Z	s3.amazonaws.com	GetBucketEncryption
2026-02-11T15:22:11Z	s3.amazonaws.com	GetBucketPolicy
2026-02-11T15:22:13Z	s3.amazonaws.com	GetBucketPublicAccessBlock
2026-02-11T15:22:21Z	s3.amazonaws.com	GetBucketAcl
2026-02-11T15:22:21Z	s3.amazonaws.com	GetBucketPolicy
2026-02-11T15:22:21Z	s3.amazonaws.com	GetBucketEncryption
2026-02-11T15:22:21Z	s3.amazonaws.com	GetBucketPublicAccessBlock
2026-02-11T15:22:32Z	lambda.amazonaws.com	ListFunctions20150331
2026-02-11T15:22:24Z	dynamodb.amazonaws.com	ListTables
```
With this command you can evaluate also the time correlation between each event, and check if probably is tool automated or not.

### 4. AccessDenied Spikes
Burst of failed calls indicating permission probing. It is important to correlate during the scan the `AccessDenied` error because detecting dense AccessDenied clusters can allow early interruption of malicious activity. High-volume read calls combined with denied responses significantly increase confidence that the activity represents reconnaissance rather than normal workload behavior.

``` bash
jq -r '
  .Records[] |
  select(
    (.eventName? // "" | test("^(Get|List|Describe)")) and
    (.userAgent? // "" | test("aws-cli|boto|botocore|Boto3")) and
    (.errorCode? == "AccessDenied")
  ) |
  [.eventTime, .userIdentity.arn, .eventName] |
  @tsv
' *.json
2026-02-11T15:22:32Z	arn:aws:iam::137809406849:user/bob	ListFunctions20150331
2026-02-11T15:22:24Z	arn:aws:iam::137809406849:user/bob	ListTables
2026-02-11T15:47:11Z	arn:aws:iam::137809406849:user/bob	ListFunctions20150331
2026-02-11T17:00:51Z	arn:aws:iam::137809406849:user/bob	ListTables
2026-02-11T17:00:51Z	arn:aws:iam::137809406849:user/bob	ListFunctions20150331
```

## Why This Matters

Early detection of enumeration activity allows:

- Rapid identification of compromised credentials
- Interruption of the attacker kill chain
- Prevention of privilege escalation and lateral movement

Cloud-native reconnaissance leaves strong API footprints.
Understanding those patterns enables proactive detection engineering.

## Lessons Learned
This lab shows that AWS reconnaissance is API-driven and leaves clear behavioral traces in CloudTrail. Suspicious activity is not defined by single events, but by patterns:
- High-volume List*, Get*, Describe* calls
- Cross-service sweeps within short time windows
- Bursts of AccessDenied errors indicating permission probing
- Automation user agents and dense temporal clustering

Time-based aggregation and identity correlation significantly increase detection confidence. Even without a SIEM, raw CloudTrail analysis can reveal early-stage credential misuse.                               

The key takeaway: early cloud reconnaissance produces detectable API fingerprints, and proper correlation enables interruption before escalation or lateral movement.
