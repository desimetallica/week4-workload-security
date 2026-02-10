# week1-hardening-lab

## Objective

We want to make a simple lab with a simulation of first phases of kill-chain on AWS account.
We try to simulate a possible recon tool running and we try to understand how behave in Cloud-Trails logs to understand how 
an attacker could move an check permissions and capabilies on AWS cloud.


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
6. Run the Ansible playbook check details on ./ansible/README.md
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

## Recon Script 
- `config/recon.py`

## Lessons Learned

