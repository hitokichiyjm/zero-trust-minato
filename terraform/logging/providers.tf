# 管理アカウント(既定:組織の CloudTrail)と、log-archive アカウント(ログ用 S3)
locals {
  default_tags = {
    Project   = var.project
    ManagedBy = "terraform"
    Stack     = "logging"
  }
}

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.management_account_id]

  default_tags {
    tags = local.default_tags
  }
}

provider "aws" {
  alias  = "log"
  region = var.aws_region

  assume_role {
    role_arn     = "arn:aws:iam::${local.log_id}:role/${var.member_role_name}"
    session_name = "terraform-logging"
  }

  default_tags {
    tags = local.default_tags
  }
}
