# ID 基盤:IAM Identity Center のグループ、許可セット、アカウントへの割り当て(DOC-03 5.1)
#
# P0 で手動で作ったもの(g-it-admin、AdministratorAccess、管理アカウントへの割り当て、自分の所属)は
# scripts/import-identity.sh で取り込む。
# MFA の設定(FIDO2 のみ)は Terraform で管理できないため、画面で設定している(DOC-03 5.2)。

data "aws_ssoadmin_instances" "this" {}

data "aws_organizations_organization" "this" {}

locals {
  instance_arn      = tolist(data.aws_ssoadmin_instances.this.arns)[0]
  identity_store_id = tolist(data.aws_ssoadmin_instances.this.identity_store_ids)[0]

  # アカウントの名前から ID を引く(org スタックで作った名前)
  account_ids = {
    management = data.aws_organizations_organization.this.master_account_id
    security   = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-security"])
    log        = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-log-archive"])
    prod       = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-prod"])
    dev        = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-dev"])
  }
}

# ---- グループ(役割) ----
locals {
  groups = {
    "g-it-admin"   = "情報システム担当(兼務)"
    "g-executive"  = "代表"
    "g-developer"  = "開発"
    "g-sales"      = "営業"
    "g-backoffice" = "経理・総務"
    "g-contractor" = "外部委託者"
  }
}

resource "aws_identitystore_group" "this" {
  for_each = local.groups

  identity_store_id = local.identity_store_id
  display_name      = each.key
  description       = each.value
}

# 自分(情報システム担当)を g-it-admin に入れる
data "aws_identitystore_user" "admin" {
  identity_store_id = local.identity_store_id

  alternate_identifier {
    unique_attribute {
      attribute_path  = "UserName"
      attribute_value = var.admin_user_name
    }
  }
}

resource "aws_identitystore_group_membership" "admin" {
  identity_store_id = local.identity_store_id
  group_id          = aws_identitystore_group.this["g-it-admin"].group_id
  member_id         = data.aws_identitystore_user.admin.user_id
}

# ---- 許可セット(権限のひな形) ----
locals {
  permission_sets = {
    AdministratorAccess = {
      description      = "Full admin. For g-it-admin only"
      session          = "PT1H"
      managed_policies = ["arn:aws:iam::aws:policy/AdministratorAccess"]
    }
    ReadOnlyAccess = {
      description      = "Read-only access"
      session          = "PT4H"
      managed_policies = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
    }
    Developer = {
      description      = "Developer access without IAM management"
      session          = "PT4H"
      managed_policies = ["arn:aws:iam::aws:policy/PowerUserAccess"]
    }
    DashboardViewer = {
      description      = "View CloudWatch dashboards only"
      session          = "PT4H"
      managed_policies = []
    }
  }

  managed_policy_attachments = merge([
    for ps, v in local.permission_sets : {
      for p in v.managed_policies : "${ps}:${element(split("/", p), length(split("/", p)) - 1)}" => { ps = ps, policy = p }
    }
  ]...)
}

resource "aws_ssoadmin_permission_set" "this" {
  for_each = local.permission_sets

  instance_arn     = local.instance_arn
  name             = each.key
  description      = each.value.description
  session_duration = each.value.session
}

resource "aws_ssoadmin_managed_policy_attachment" "this" {
  for_each = local.managed_policy_attachments

  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.value.ps].arn
  managed_policy_arn = each.value.policy
}

# 代表がダッシュボードを見るための、最小限の権限
data "aws_iam_policy_document" "dashboard_viewer" {
  # ダッシュボードは、このプロジェクトのものだけ
  statement {
    sid       = "ViewProjectDashboards"
    effect    = "Allow"
    actions   = ["cloudwatch:GetDashboard"]
    resources = ["arn:aws:cloudwatch::*:dashboard/${var.project}-*"]
  }

  # アラームの状態は、このリージョンのものだけ
  statement {
    sid       = "ViewAlarms"
    effect    = "Allow"
    actions   = ["cloudwatch:DescribeAlarms"]
    resources = ["arn:aws:cloudwatch:${var.aws_region}:*:alarm:*"]
  }

  # 次の操作はリソースを指定できない(AWS の仕様)ため "*" にする。どれも読み取りだけ
  statement {
    sid    = "ReadMetrics"
    effect = "Allow"
    actions = [
      "cloudwatch:GetMetricData",
      "cloudwatch:GetMetricStatistics",
      "cloudwatch:ListDashboards",
      "cloudwatch:ListMetrics",
    ]
    resources = ["*"]
  }
}

resource "aws_ssoadmin_permission_set_inline_policy" "dashboard_viewer" {
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this["DashboardViewer"].arn
  inline_policy      = data.aws_iam_policy_document.dashboard_viewer.json
}

# ---- 割り当て(誰が、どのアカウントで、どの権限を使えるか) ----
# 営業・経理・外部委託者には AWS の権限を渡さない(使うのは社内アプリだけ。P2 の ZTNA で制御する)
locals {
  assignments = concat(
    [for acct in ["management", "security", "log", "prod", "dev"] : { group = "g-it-admin", ps = "AdministratorAccess", account = acct }],
    [
      { group = "g-executive", ps = "DashboardViewer", account = "security" },
      { group = "g-developer", ps = "Developer", account = "dev" },
      { group = "g-developer", ps = "ReadOnlyAccess", account = "prod" },
    ],
  )
}

resource "aws_ssoadmin_account_assignment" "this" {
  for_each = { for a in local.assignments : "${a.group}:${a.ps}:${a.account}" => a }

  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.value.ps].arn
  principal_type     = "GROUP"
  principal_id       = aws_identitystore_group.this[each.value.group].group_id
  target_type        = "AWS_ACCOUNT"
  target_id          = local.account_ids[each.value.account]

  # 許可セットの中身(ポリシー)ができてから割り当てる
  depends_on = [
    aws_ssoadmin_managed_policy_attachment.this,
    aws_ssoadmin_permission_set_inline_policy.dashboard_viewer,
  ]
}
