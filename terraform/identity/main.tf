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

# ---- 検証用の利用者(P2-2b、受け入れ基準 AC-1 の確認に使う) ----
# メールは Gmail の「+」の別名(例:name+sales@gmail.com)。元のアドレスは公開しないので変数から渡す。
# パスワードとパスキー(FIDO2)の登録は、利用者本人(=自分)が画面で行う。
locals {
  test_email_parts = split("@", var.test_email_base)

  test_users = {
    "t-sales" = {
      given  = "営業"
      family = "検証"
      group  = "g-sales"
      tag    = "sales"
    }
    # AC-1(AWS):検証(dev)は Developer、本番(prod)は読み取りだけ、ほかのアカウントには入れないことを示す
    "t-developer" = {
      given  = "開発"
      family = "検証"
      group  = "g-developer"
      tag    = "developer"
    }
    # 外部委託者は契約の終了日(expires)を書く(FR-ID-06、DOC-03 5.3)。その日の 0 時(日本時間)から使えなくなる
    "t-contractor" = {
      given   = "委託"
      family  = "検証"
      group   = "g-contractor"
      tag     = "contractor"
      expires = "2027-03-31"
    }
  }

  # 期限を過ぎた人は、グループの所属を作らない(期限切れの Lambda が外したあとに、Terraform が作り直さないため)
  active_test_users = {
    for k, v in local.test_users : k => v
    if try(v.expires, null) == null || timecmp(plantimestamp(), "${try(v.expires, "2999-12-31")}T00:00:00+09:00") < 0
  }
}

resource "aws_identitystore_user" "test" {
  for_each = local.test_users

  identity_store_id = local.identity_store_id
  user_name         = each.key
  display_name      = "${each.value.family} ${each.value.given}"

  name {
    given_name  = each.value.given
    family_name = each.value.family
  }

  emails {
    value   = "${local.test_email_parts[0]}+${each.value.tag}@${local.test_email_parts[1]}"
    primary = true
    type    = "work"
  }

  lifecycle {
    # 期限(expires)を書けるのは外部委託者(g-contractor)だけ。形は YYYY-MM-DD。書き間違いで期限が効かないのを防ぐ
    precondition {
      condition     = try(each.value.expires, null) == null || (each.value.group == "g-contractor" && can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", try(each.value.expires, ""))))
      error_message = "expires は g-contractor の利用者にだけ、YYYY-MM-DD の形で書いてください。"
    }
  }
}

resource "aws_identitystore_group_membership" "test" {
  for_each = local.active_test_users

  identity_store_id = local.identity_store_id
  group_id          = aws_identitystore_group.this[each.value.group].group_id
  member_id         = aws_identitystore_user.test[each.key].user_id
}
