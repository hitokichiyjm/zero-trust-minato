# 管理アカウント(既定)と、4つのメンバーアカウント(ロールを引き受ける)
locals {
  default_tags = {
    Project   = var.project
    ManagedBy = "terraform"
    Stack     = "ztna"
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
  alias  = "prod"
  region = var.aws_region

  assume_role {
    role_arn     = "arn:aws:iam::${local.account_ids.prod}:role/${var.member_role_name}"
    session_name = "terraform-ztna"
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
    session_name = "terraform-ztna"
  }

  default_tags {
    tags = local.default_tags
  }
}

# Cloudflare:トークンは環境変数 CLOUDFLARE_API_TOKEN から読む(コードやファイルには書かない)
#   手元:Mac のキーチェーンに保存した編集用のトークン
#   CI  :GitHub の Secret の読み取り専用のトークン
provider "cloudflare" {}
