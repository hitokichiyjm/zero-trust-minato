# 管理アカウント(組織の情報を読む)と、security アカウント(ダッシュボードと集計の Lambda を置く)
locals {
  default_tags = {
    Project   = var.project
    ManagedBy = "terraform"
    Stack     = "dashboard"
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
  alias  = "security"
  region = var.aws_region

  assume_role {
    role_arn     = "arn:aws:iam::${local.account_ids.security}:role/${var.member_role_name}"
    session_name = "terraform-dashboard"
  }

  default_tags {
    tags = local.default_tags
  }
}
