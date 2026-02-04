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

variable "s3_workload_bucket_name" {
  description = "Name of the S3 bucket to be created"
  type        = string
}

variable "s3_cloudtrail_bucket_name" {
  description = "Name of the S3 bucket for CloudTrail logs"
  type        = string
}

variable "admin_user_name" {
  description = "Name of the admin IAM user"
  type        = string
}

variable "developer_user_name" {
  description = "Name of the developer IAM user"
  type        = string
}

variable "readonly_user_name" {
  description = "Name of the readonly IAM user"
  type        = string
}

variable "admin_group_name" {
  description = "Name of the admin IAM group"
  type        = string
}

variable "developer_group_name" {
  description = "Name of the developer IAM group"
  type        = string
}

variable "readonly_group_name" {
  description = "Name of the readonly IAM group"
  type        = string
}

