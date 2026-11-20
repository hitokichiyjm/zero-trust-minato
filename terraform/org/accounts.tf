# メンバーアカウント(DOC-03 4.1)
# メールアドレスは公開しないため、terraform.tfvars(Git に入らない)から渡す。
locals {
  accounts = {
    security = { name = "${var.project}-security", ou = "security" }
    log      = { name = "${var.project}-log-archive", ou = "security" }
    prod     = { name = "${var.project}-prod", ou = "workloads" }
    dev      = { name = "${var.project}-dev", ou = "workloads" }
  }

  ou_ids = {
    security  = aws_organizations_organizational_unit.security.id
    workloads = aws_organizations_organizational_unit.workloads.id
  }
}

resource "aws_organizations_account" "this" {
  for_each = local.accounts

  name      = each.value.name
  email     = var.account_emails[each.key]
  parent_id = local.ou_ids[each.value.ou]

  # 管理アカウントから入るためのロール。Terraform もこのロールで各アカウントを操作する
  role_name = "OrganizationAccountAccessRole"

  # 請求情報は管理アカウントでまとめて見るため、メンバーアカウントの IAM には見せない
  iam_user_access_to_billing = "DENY"

  # terraform destroy のときにアカウントを閉鎖する(組織から外すだけだと、単独のアカウントとして課金が続くため)
  close_on_deletion = true

  lifecycle {
    # 誤って消さないように。削除するときは外す(DOC-04 OP-43)
    prevent_destroy = true
    # role_name と iam_user_access_to_billing は作成時だけの設定で、後から読み取れないため差分を無視する
    ignore_changes = [role_name, iam_user_access_to_billing]
  }
}
