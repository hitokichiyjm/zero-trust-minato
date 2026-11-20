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
}

# 管理アカウント(CI のロールは bootstrap にあるので作らない)
module "management" {
  source  = "../modules/account-baseline"
  project = var.project
}

module "security" {
  source           = "../modules/account-baseline"
  providers        = { aws = aws.security }
  project          = var.project
  ci_plan_role_arn = data.aws_iam_role.github_plan.arn
}

module "log" {
  source           = "../modules/account-baseline"
  providers        = { aws = aws.log }
  project          = var.project
  ci_plan_role_arn = data.aws_iam_role.github_plan.arn
}

module "prod" {
  source           = "../modules/account-baseline"
  providers        = { aws = aws.prod }
  project          = var.project
  ci_plan_role_arn = data.aws_iam_role.github_plan.arn
}

module "dev" {
  source           = "../modules/account-baseline"
  providers        = { aws = aws.dev }
  project          = var.project
  ci_plan_role_arn = data.aws_iam_role.github_plan.arn
}
