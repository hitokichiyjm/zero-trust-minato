# 管理アカウント(既定)と、4つのメンバーアカウント(ロールを引き受ける)
locals {
  default_tags = {
    Project   = var.project
    ManagedBy = "terraform"
    Stack     = "response"
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
    session_name = "terraform-response"
  }

  default_tags {
    tags = local.default_tags
  }
}

provider "aws" {
  alias  = "log"
  region = var.aws_region

  assume_role {
    role_arn     = "arn:aws:iam::${local.account_ids.log}:role/${var.member_role_name}"
    session_name = "terraform-response"
  }

  default_tags {
    tags = local.default_tags
  }
}

provider "aws" {
  alias  = "prod"
  region = var.aws_region

  assume_role {
    role_arn     = "arn:aws:iam::${local.account_ids.prod}:role/${var.member_role_name}"
    session_name = "terraform-response"
  }

  default_tags {
    tags = local.default_tags
  }
}

provider "aws" {
  alias  = "dev"
  region = var.aws_region

  assume_role {
    role_arn     = "arn:aws:iam::${local.account_ids.dev}:role/${var.member_role_name}"
    session_name = "terraform-response"
  }

  default_tags {
    tags = local.default_tags
  }
}

# ルートユーザーのコンソールへのサインインは、us-east-1 に記録されることがあるため、管理アカウントの us-east-1 でも受け取る
provider "aws" {
  alias               = "management_us_east_1"
  region              = "us-east-1"
  allowed_account_ids = [var.management_account_id]

  default_tags {
    tags = local.default_tags
  }
}
