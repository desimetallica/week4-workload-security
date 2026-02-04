provider "aws" {
  region = var.aws_region
}

# Get current account number
data "aws_caller_identity" "current" {}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_key_pair" "deployer" {
  key_name   = var.ssh_key_name
  public_key = file(var.ssh_public_key_path)
}

resource "aws_security_group" "web_access" {
  name        = "allow_ssh_http"
  description = "Allow SSH and HTTP inbound traffic"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # restrict to your IP for security
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # restrict to your IP for security
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "example" {
  ami           = var.ami_id
  instance_type = var.instance_type
  vpc_security_group_ids = [aws_security_group.web_access.id]
  key_name      = aws_key_pair.deployer.key_name
  tags = {
    Name = "TerraformExampleEC2"
  }
}





#
#
# S3 Buckets
#
# non predictable S3 bucket name to avoid conflicts
resource "aws_s3_bucket" "workload_bucket" {
  bucket = "${var.s3_workload_bucket_name}-${random_id.bucket_suffix.hex}"
  force_destroy = true

  lifecycle {
    prevent_destroy = false
  }
}

# disable S3 versioning to reduce storage costs and prevent unintended sensible data retention
resource "aws_s3_bucket_versioning" "workload_bucket_versioning" {
  bucket = aws_s3_bucket.workload_bucket.id
  
  versioning_configuration {
    status = "Suspended"
  }
}

resource "aws_s3_bucket_ownership_controls" "workload_bucket_ownership" {
  bucket = aws_s3_bucket.workload_bucket.id
  
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Enable Server Side Encryption with AES256
resource "aws_s3_bucket_server_side_encryption_configuration" "workload_bucket_sse" {
    bucket = aws_s3_bucket.workload_bucket.id
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
}

# add Block Public Access to S3 Bucket to protect against public access and future misconfiguration
resource "aws_s3_bucket_public_access_block" "workload_bucket_public_access_block" {
  bucket = aws_s3_bucket.workload_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}



# S3 Bucket policy deny non TLS requests, explicitly deny public access.
resource "aws_s3_bucket_policy" "workload_bucket_policy" {
  
  bucket = aws_s3_bucket.workload_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLSRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.workload_bucket.arn,
          "${aws_s3_bucket.workload_bucket.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]      
  })
}



#
#
# Cloud trail S3 bucket with correct permissions and policies to receive logs from CloudTrail
#
# non predictable S3 bucket name to avoid conflicts
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "${var.s3_cloudtrail_bucket_name}-${random_id.bucket_suffix.hex}"
  force_destroy = true
  
  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs_versioning" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration {
    status = "Disabled"
  }
}

resource "aws_s3_bucket_ownership_controls" "cloudtrail_logs_ownership" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Enable Server Side Encryption with AES256
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_bucket_sse" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Add Block Public Access to S3 Bucket to protect against public access and future misconfiguration
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs_public_access_block" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail_logs_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLSRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail_logs.arn,
          "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

#
#
# AWS CloudTrail 
#
#
resource "aws_cloudtrail" "main" {
  depends_on = [
    aws_s3_bucket_policy.cloudtrail_logs_policy
  ]
  name                          = var.s3_cloudtrail_bucket_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = []
    }
  }
}

#
#
# IAM Role: AdminRole for backend/infra
#
#
resource "aws_iam_role" "admin_role" {
  name = "AdminRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "admin_role_admin_access" {
  role       = aws_iam_role.admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

#
#
# IAM Users and Groups
#
#
resource "aws_iam_group" "admins" {
  name = var.admin_group_name
}

resource "aws_iam_group" "developers" {
  name = var.developer_group_name
}

resource "aws_iam_group" "readonly" {
  name = var.readonly_group_name
}

data "aws_iam_policy_document" "admin" {
  statement {
    actions   = ["*"]
    resources = ["*"]
    effect    = "Allow"
  }
}

resource "aws_iam_policy" "admin_policy" {
  name        = "AdminPolicy"
  description = "Full admin access"
  policy      = data.aws_iam_policy_document.admin.json
}

#
#
# Developer and Readonly Policies
#
#
data "aws_iam_policy_document" "developer" {
  statement {
    actions   = [
      "ec2:Describe*",
      "s3:List*",
      "s3:Get*",
      "s3:Put*",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:Get*",
      "dynamodb:PutItem",
      "lambda:InvokeFunction",
      "lambda:CreateFunction"
    ]
    resources = ["*"]
    effect    = "Allow"
  }
  # Adding the iam:PassRole permission to allow developers to invoke Lambda 
  # functions with the AdminRole, but not to manage the role itself
  statement {
  actions = ["iam:PassRole"]
  resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/AdminRole"]
  effect = "Allow"
  }
}

resource "aws_iam_policy" "developer_policy" {
  name        = "DeveloperPolicy"
  description = "Developer access"
  policy      = data.aws_iam_policy_document.developer.json
}

data "aws_iam_policy_document" "readonly" {
  statement {
    actions   = [
      "ec2:Describe*",
      "s3:List*",
      "s3:Get*",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:Get*"
    ]
    resources = ["*"]
    effect    = "Allow"
  }
}

resource "aws_iam_policy" "readonly_policy" {
  name        = "ReadOnlyPolicy"
  description = "Read-only access"
  policy      = data.aws_iam_policy_document.readonly.json
}

resource "aws_iam_group_policy_attachment" "admin_attach" {
  group      = aws_iam_group.admins.name
  policy_arn = aws_iam_policy.admin_policy.arn
}

resource "aws_iam_group_policy_attachment" "developer_attach" {
  group      = aws_iam_group.developers.name
  policy_arn = aws_iam_policy.developer_policy.arn
}

resource "aws_iam_group_policy_attachment" "readonly_attach" {
  group      = aws_iam_group.readonly.name
  policy_arn = aws_iam_policy.readonly_policy.arn
}

resource "aws_iam_user" "alice" {
  name = var.admin_user_name
}

resource "aws_iam_user" "bob" {
  name = var.developer_user_name
}

resource "aws_iam_user" "carol" {
  name = var.readonly_user_name
}

resource "aws_iam_user_group_membership" "alice_admin" {
  user = aws_iam_user.alice.name
  groups = [aws_iam_group.admins.name]
}

resource "aws_iam_user_group_membership" "bob_developer" {
  user = aws_iam_user.bob.name
  groups = [aws_iam_group.developers.name]
}

resource "aws_iam_user_group_membership" "carol_readonly" {
  user = aws_iam_user.carol.name
  groups = [aws_iam_group.readonly.name]
}

resource "aws_iam_user_login_profile" "carol_console" {
  user    = aws_iam_user.carol.name
  # Optionally, set a password or let AWS generate one
}