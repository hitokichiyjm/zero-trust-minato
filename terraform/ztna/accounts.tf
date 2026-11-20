data "aws_organizations_organization" "this" {}

locals {
  account_ids = {
    prod = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-prod"])
    dev  = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-dev"])
  }
}
