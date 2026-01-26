# Host Hardening with Ansible

This folder contains an Ansible playbook for hardening your hosts.


## Playbooks

- `host_hardening.yml`: Main playbook to apply security hardening to hosts.
- `verify_host_hardening.yml`: Playbook to verify that all hardening steps have been correctly applied.

## Usage Instructions

1. **Prepare your inventory:**
   - Edit the `hosts` file to list the target machines you want to harden.
   - Prepare Vault file with command:
   `ansible-vault edit vault.yaml`
   with the following variables:

```
  sysadmin_password: "12345"
  ubuntu_password: "Ubuntu12345!"
  ec2_user_password: "Ec2user12345!"
  root_password: "Ubuntu12345!
```

2. **Vault and Become Passwords:**
   - The playbook may require Ansible Vault and privilege escalation (become) passwords. Make sure you have these ready.

3. **Run the playbook:**
   - Execute the following command from this directory:
     
     ```sh
     ansible-playbook -i hosts host_hardening.yml -v --ask-vault-pass --ask-become-pass
     ```
   - `-i hosts` specifies the inventory file.
   - `host_hardening.yml` is the playbook file.
   - `-v` enables verbose output.
   - `--ask-vault-pass` prompts for the vault password if encrypted variables are used. 
   - `--ask-become-pass` prompts for the sudo password if privilege escalation is required (vault var: ec2_user_password).


4. **Verify the hardening:**
   - After running the main playbook, you can verify the configuration and security settings:
     ```sh
     ansible-playbook -i hosts verify_host_hardening.yaml -v --ask-vault-pass --ask-become-pass
     ```
   - This playbook checks:
     - User and password setup (ec2-user, root, sysadmin)
     - Firewall status and rules (firewalld or UFW)
     - SSH configuration (root login and password authentication)
     - Fail2Ban installation and configuration
     - Existence of backup `.tar.gz` files in `/root/`
     - Sudoers configuration for ec2-user (Amazon Linux)
   - The results will be displayed at the end of the playbook run for review.

5. **Customize as needed:**
   - You can modify `host_hardening.yml` or `verify_host_hardening.yml` to suit your environment or add roles and tasks as needed.

## Additional Notes
- Ensure Ansible is installed on your control machine.
- Review the playbook and inventory for accuracy before running.
- For more details, see the [Ansible documentation](https://docs.ansible.com/).

## Automated System Configuration Backup
- At the end of the playbook execution, the script `sysconf_backup.sh` is run automatically.
- This script creates a backup archive of important system configuration files and directories, storing it in `/root` with a timestamped filename.
- You can find the backup file path in the playbook output or by checking `/root` on the target machine.
