# 管理アカウントで動かす(Identity Center は管理アカウントの東京リージョンにある)。認証情報は AWS_PROFILE(SSO)か、GitHub Actions の OIDC から受け取る。
provider "aws" {
  region = var.aws_region

  allowed_account_ids = [var.management_account_id]

  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
      Stack     = "identity"
    }
  }
}
