# 組織そのもの(P0 で手動で有効にしたものを import して管理する)
#
# aws_service_access_principals は「組織が信頼するサービス」の一覧。
# 一覧から外すと、そのサービスの組織連携が切れる(例:sso.amazonaws.com を外すと Identity Center が使えなくなる)。
# そのため、import の前に今の一覧を確かめ、必要なものはすべて残す。
locals {
  service_access_principals = sort(distinct(concat([
    "sso.amazonaws.com",                      # IAM Identity Center(P0 で有効化済み)
    "cloudtrail.amazonaws.com",               # 組織の証跡(P1-3)
    "config.amazonaws.com",                   # Config(P1-3)
    "config-multiaccountsetup.amazonaws.com", # Config の組織ルール・アグリゲーター(P1-3)
    "guardduty.amazonaws.com",                # GuardDuty(P1-3)
    "malware-protection.guardduty.amazonaws.com",
    "securityhub.amazonaws.com",     # Security Hub(P1-3)
    "access-analyzer.amazonaws.com", # IAM Access Analyzer(P1-3)
    "account.amazonaws.com",         # アカウントの連絡先などの一括管理
    "iam.amazonaws.com",             # メンバーアカウントのルートユーザーの一括管理
  ], var.extra_service_access_principals)))
}

resource "aws_organizations_organization" "this" {
  feature_set                   = "ALL"
  aws_service_access_principals = local.service_access_principals
  enabled_policy_types          = ["SERVICE_CONTROL_POLICY"]

  lifecycle {
    prevent_destroy = true
  }
}

locals {
  root_id = aws_organizations_organization.this.roots[0].id
}

resource "aws_organizations_organizational_unit" "security" {
  name      = "Security"
  parent_id = local.root_id
}

resource "aws_organizations_organizational_unit" "workloads" {
  name      = "Workloads"
  parent_id = local.root_id
}
