# week1-hardening-lab

## Objective

We want to make a simple lab with a simulation of first phases of kill-chain on AWS account.
We try to simulate a possible recon tool running and we try to understand how this behave in Cloud-Trails logs to understand how 
an attacker could move an check permissions and capabilies on services present. 
This involves low level dive in into Cloud-Trail logs. 

## Environment

- AWS Free Tier account
- Terraform
- Ansible
- Simple recon script
- Amazon Linux 2/2023 or Ubuntu/Debian EC2 instances

Resources in our lab:

- Deploy EC2 on AWS (free tier) 
- Harden Linux (SSH, users, firewall, permissions)
- A basic Cloud-Trail deploy with S3 bucket available 
- Compromised user: bob

## Lab Preparation Steps
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


## Terraform Files
- `terraform/main.tf`: Main configuration (EC2, key pair, security group)
- `terraform/variables.tf`: Input variables
- `terraform/outputs.tf`: Outputs (including Ansible inventory)
- `terraform/defaults.tfvars`: Default variable values

## Ansible Files
- `ansible/host_hardening.yml`: Harden host (compatible with Amazon Linux, Red Hat, Debian, Ubuntu)
- `ansible/workload_config.yml`: Workload configuration playbook (simple httpd service)
- `ansible/hosts`: Inventory file (generated from Terraform output)
- `ansible/sysconf_backup.sh`: Bash script for config backup
- `ansible/verify_host_hardening.yml`: Configuration check

## Config FIles
- `config/recon.py`: Recon simulation script
- `config/lambda_function.py`: the privilege escalation lambda function used
- `config/index.html`: some sample html workload

## Lab Execution
In this lab environment, the deployed infrastructure consists of a Virtual Private Cloud (VPC) that serves as the foundational network layer for all resources. Within this VPC, there are subnets, route tables, security groups, and EC2 instances configured to simulate a typical cloud workload. The setup includes public-facing components, such as an EC2 instance accessible via SSH and HTTP, and S3 buckets for application data and CloudTrail logs. Security groups define the allowed inbound and outbound traffic, while IAM roles and policies manage user and service permissions. 

This environment provides a realistic playground for an attacker to perform reconnaissance activities, such as enumerating VPCs, subnets, route tables, gateways, security groups, and instances, as well as probing for accessible storage and privilege escalation opportunities. The recon phase in this context would involve mapping the network structure, identifying exposed services, and understanding the security boundaries and potential attack paths within the cloud infrastructure.


### Assumptions
Assumptions: 
- The user “bob” (simulating a developer or compromised user) exists and has the necessary IAM permissions as defined in the Terraform configuration.
- A local iam configured profile `aws configure --profile bob`

### Reconnaissance Phase
The `recon.py` script simulates an AWS reconnaissance phase performed by a low-privileged IAM user (`bob`) using automated SDK/API calls. In an AWS environment, reconnaissance does not involve traditional network scanning but API-driven enumeration of cloud resources. The script performs systematic `List*`, `Get*`, and `Describe*` operations across services such as IAM, EC2, S3, Lambda, dynamodb to map the account structure, VPC topology, security groups, IAM roles, and attached policies. This activity emulates how an attacker profiles permissions, identifies privilege escalation paths (e.g., over-privileged roles or PassRole opportunities), and evaluates lateral movement potential. The resulting CloudTrail logs are used to analyze enumeration bursts, cross-service access patterns, automation user agents (boto3/aws-cli), and AccessDenied probing, enabling detection engineering and behavioral analysis of cloud-native reconnaissance techniques.

Once we assume a credential compromise scenario (e.g., a malicious actor in possession of the IAM user `bob` credentials), the first logical attacker phase is capability discovery through API enumeration. In AWS, this reconnaissance phase manifests as systematic `Get*`, `List*`, and `Describe*` calls across multiple services to understand identity permissions, resource exposure, and potential privilege escalation paths. Typical early-stage probes include `sts:GetCallerIdentity`, `iam:GetUser`, `iam:ListAttachedUserPolicies`, `s3:ListBuckets`, `ec2:DescribeSecurityGroups`, and similar read-oriented APIs.

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

To detect this behavior, CloudTrail log hunting focuses on identifying enumeration patterns, cross-service sweeps, and burst activity within short time windows. Using `jq`, it is possible to filter CloudTrail records for a specific principal and isolate `Get|List|Describe` events, correlating them by timestamp and service. This enables detection of automated reconnaissance, especially when combined with user agent analysis (e.g., `aws-cli`, `boto3`, `botocore`) and minute-level aggregation to highlight high-density API activity.

In the simulated scenario, the `recon.py` script generates a concentrated scan across services (S3, EC2, Lambda, DynamoDB) within seconds, clearly visible in CloudTrail as a burst of enumeration calls. By grouping events per identity and time slice, and counting service diversity, it becomes possible to distinguish normal operational activity from scripted reconnaissance. This approach demonstrates practical detection engineering capabilities: correlating identity, API pattern, service spread, automation fingerprinting, and temporal density to identify cloud-native reconnaissance behavior.



### Priviledge Escalation phase


## Lessons Learned

