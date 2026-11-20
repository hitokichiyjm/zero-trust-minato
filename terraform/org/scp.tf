# SCP(DOC-03 4.2)
# FullAWSAccess は付けたままにし、「やってはいけないこと」だけを Deny で禁止する(拒否リスト方式)。
# SCP は管理アカウントには効かない。

locals {
  # Terraform が各アカウントを操作するときに使うロール。設定の変更を許すため、一部の SCP で例外にする
  terraform_role_arn_pattern = "arn:aws:iam::*:role/OrganizationAccountAccessRole"
}

# ---- 組織から抜けることを禁止(Root) ----
data "aws_iam_policy_document" "deny_leave_org" {
  statement {
    sid       = "DenyLeaveOrganization"
    effect    = "Deny"
    actions   = ["organizations:LeaveOrganization"]
    resources = ["*"]
  }
}

# ---- 東京リージョン以外の利用を禁止 ----
# グローバルサービス(IAM、Organizations、請求など)は us-east-1 などで動くため対象外にする
data "aws_iam_policy_document" "region_restrict" {
  statement {
    sid    = "DenyOutsideAllowedRegion"
    effect = "Deny"
    not_actions = [
      "account:*",
      "aws-portal:*",
      "billing:*",
      "budgets:*",
      "ce:*",
      "cloudfront:*",
      "cur:*",
      "freetier:*",
      "globalaccelerator:*",
      "health:*",
      "iam:*",
      "invoicing:*",
      "networkmanager:*",
      "notifications:*",
      "organizations:*",
      "payments:*",
      "pricing:*",
      "route53:*",
      "route53domains:*",
      "s3:GetAccountPublic*",
      "s3:ListAllMyBuckets",
      "s3:PutAccountPublic*",
      "shield:*",
      "sts:*",
      "support:*",
      "tax:*",
      "trustedadvisor:*",
      "waf:*",
    ]
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }
}

# ---- 検知とログの仕組みを止めることを禁止 ----
data "aws_iam_policy_document" "protect_security" {
  statement {
    sid    = "DenyDisablingSecurityServices"
    effect = "Deny"
    actions = [
      "cloudtrail:DeleteTrail",
      "cloudtrail:PutEventSelectors",
      "cloudtrail:StopLogging",
      "cloudtrail:UpdateTrail",
      "guardduty:DeleteDetector",
      "guardduty:DeleteMembers",
      "guardduty:DisassociateFromAdministratorAccount",
      "guardduty:DisassociateFromMasterAccount",
      "guardduty:DisassociateMembers",
      "guardduty:StopMonitoringMembers",
      "guardduty:UpdateDetector",
      "securityhub:DeleteMembers",
      "securityhub:DisableSecurityHub",
      "securityhub:DisassociateFromAdministratorAccount",
      "securityhub:DisassociateFromMasterAccount",
      "securityhub:DisassociateMembers",
      "config:DeleteConfigurationAggregator",
      "config:DeleteConfigurationRecorder",
      "config:DeleteDeliveryChannel",
      "config:StopConfigurationRecorder",
      "access-analyzer:DeleteAnalyzer",
    ]
    resources = ["*"]

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = [local.terraform_role_arn_pattern]
    }
  }
}

# ---- IAM ユーザーと長期の認証情報を作ることを禁止 ----
data "aws_iam_policy_document" "deny_iam_user" {
  statement {
    sid    = "DenyLongTermCredentials"
    effect = "Deny"
    actions = [
      "iam:CreateAccessKey",
      "iam:CreateLoginProfile",
      "iam:CreateUser",
    ]
    resources = ["*"]
  }
}

# ---- ログ用 S3 を守る(log-archive アカウント) ----
data "aws_iam_policy_document" "protect_logs" {
  statement {
    sid    = "DenyTamperingLogBuckets"
    effect = "Deny"
    actions = [
      "s3:DeleteBucket",
      "s3:DeleteBucketPolicy",
      "s3:PutBucketObjectLockConfiguration",
      "s3:PutBucketPolicy",
      "s3:PutBucketVersioning",
      "s3:PutLifecycleConfiguration",
    ]
    resources = ["arn:aws:s3:::${var.project}-logs-*"]

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = [local.terraform_role_arn_pattern]
    }
  }
}

locals {
  scps = {
    deny-leave-org   = { doc = data.aws_iam_policy_document.deny_leave_org.json, desc = "Deny leaving the organization" }
    region-restrict  = { doc = data.aws_iam_policy_document.region_restrict.json, desc = "Deny use outside the allowed region" }
    protect-security = { doc = data.aws_iam_policy_document.protect_security.json, desc = "Deny disabling logging and detection services" }
    deny-iam-user    = { doc = data.aws_iam_policy_document.deny_iam_user.json, desc = "Deny IAM users and long-term credentials" }
    protect-logs     = { doc = data.aws_iam_policy_document.protect_logs.json, desc = "Deny tampering with log buckets" }
  }

  # どの SCP をどこに付けるか
  scp_attachments = {
    "deny-leave-org:root"        = { scp = "deny-leave-org", target = local.root_id }
    "region-restrict:security"   = { scp = "region-restrict", target = aws_organizations_organizational_unit.security.id }
    "region-restrict:workloads"  = { scp = "region-restrict", target = aws_organizations_organizational_unit.workloads.id }
    "protect-security:security"  = { scp = "protect-security", target = aws_organizations_organizational_unit.security.id }
    "protect-security:workloads" = { scp = "protect-security", target = aws_organizations_organizational_unit.workloads.id }
    "deny-iam-user:security"     = { scp = "deny-iam-user", target = aws_organizations_organizational_unit.security.id }
    "deny-iam-user:workloads"    = { scp = "deny-iam-user", target = aws_organizations_organizational_unit.workloads.id }
    "protect-logs:log-archive"   = { scp = "protect-logs", target = aws_organizations_account.this["log"].id }
  }
}

resource "aws_organizations_policy" "scp" {
  for_each = local.scps

  name        = "${var.project}-${each.key}"
  description = each.value.desc
  type        = "SERVICE_CONTROL_POLICY"
  content     = each.value.doc

  depends_on = [aws_organizations_organization.this]
}

resource "aws_organizations_policy_attachment" "scp" {
  for_each = local.scp_attachments

  policy_id = aws_organizations_policy.scp[each.value.scp].id
  target_id = each.value.target
}
