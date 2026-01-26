output "instance_id" {
  description = "ID of the EC2 instance"
  value       = aws_instance.example.id
}

output "public_ip" {
  description = "Public IP of the EC2 instance"
  value       = aws_instance.example.public_ip
}

output "ansible_inventory" {
  description = "Ansible inventory file content for the deployed instance(s)"
  value = <<EOT
[ec2_instances]
${aws_instance.example.public_ip} ansible_user=ec2-user ansible_ssh_private_key_file=${var.ssh_private_key_path}
EOT
}
