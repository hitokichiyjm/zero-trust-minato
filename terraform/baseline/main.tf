# 全アカウントの基本設定(DOC-03 4.3)
# 管理アカウントから、各メンバーアカウントのロールを引き受けて設定する。
#   手元:OrganizationAccountAccessRole(管理者)
#   CI  :zero-trust-minato-plan-readonly(読み取り専用。このスタックで作る)

data "aws_organizations_organization" "this" {}

data "aws_iam_role" "github_plan" {
  name = "${var.project}-github-plan"
}

locals {
  account_ids = {
    security = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-security"])
    log      = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-log-archive"])
    prod     = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-prod"])
    dev      = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-dev"])
  }

  # dashboard スタックの集計用 Lambda のロール(security)。指標③のために各アカウントの認証情報レポートを読む(P2-4)
  metrics_principal_arn = "arn:aws:iam::${local.account_ids.security}:role/${var.project}-metrics"
}

# 管理アカウント(CI のロールは bootstrap にあるので作らない)
module "management" {
  source                = "../modules/account-baseline"
  project               = var.project
  metrics_principal_arn = local.metrics_principal_arn
}

module "security" {
  source                = "../modules/account-baseline"
  providers             = { aws = aws.security }
  project               = var.project
  ci_plan_role_arn      = data.aws_iam_role.github_plan.arn
  metrics_principal_arn = local.metrics_principal_arn
}

module "log" {
  source                = "../modules/account-baseline"
  providers             = { aws = aws.log }
  project               = var.project
  ci_plan_role_arn      = data.aws_iam_role.github_plan.arn
  metrics_principal_arn = local.metrics_principal_arn
}

module "prod" {
  source                = "../modules/account-baseline"
  providers             = { aws = aws.prod }
  project               = var.project
  ci_plan_role_arn      = data.aws_iam_role.github_plan.arn
  metrics_principal_arn = local.metrics_principal_arn
}

module "dev" {
  source                = "../modules/account-baseline"
  providers             = { aws = aws.dev }
  project               = var.project
  ci_plan_role_arn      = data.aws_iam_role.github_plan.arn
  metrics_principal_arn = local.metrics_principal_arn
}
