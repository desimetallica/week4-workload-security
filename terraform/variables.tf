variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "eu-south-1"
}

variable "ami_id" {
  description = "AMI ID for the EC2 instance"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t2.micro"
}

variable "ssh_key_name" {
  description = "Name of the AWS EC2 Key Pair to use for SSH access"
  type        = string
}

variable "ssh_public_key_path" {
  description = "Path to your local SSH public key file (e.g., ~/.ssh/id_rsa.pub)"
  type        = string
}

variable "ssh_private_key_path" {
  description = "Path to your local SSH private key file (e.g., ~/.ssh/id_rsa)"
  type        = string
}
