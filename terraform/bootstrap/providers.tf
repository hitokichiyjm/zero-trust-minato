# 認証情報はコードに書かない(CI の動作確認)。手元では AWS_PROFILE(SSO のプロファイル)、
# GitHub Actions では OIDC で受け取った一時的な認証情報を使う。
provider "aws" {
  region = var.aws_region

  # 間違ったアカウントに適用しないための安全装置
  allowed_account_ids = [var.management_account_id]

  default_tags {
    tags = local.common_tags
  }
}

# Cost Explorer(コスト異常検出)の API は us-east-1 にある
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  allowed_account_ids = [var.management_account_id]

  default_tags {
    tags = local.common_tags
  }
}

locals {
  common_tags = {
    Project   = var.project
    ManagedBy = "terraform"
    Stack     = "bootstrap"
  }
}
