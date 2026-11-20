# 検知(DOC-03 7章)
# 管理は security アカウントに任せる(委任管理者)。管理アカウントは「任せる」設定だけを行う。

data "aws_organizations_organization" "this" {}

data "terraform_remote_state" "logging" {
  backend = "s3"

  config = {
    bucket = var.tfstate_bucket
    key    = "logging/terraform.tfstate"
    region = var.aws_region
  }
}

locals {
  root_id    = data.aws_organizations_organization.this.roots[0].id
  log_bucket = data.terraform_remote_state.logging.outputs.config_bucket

  account_ids = {
    security = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-security"])
    log      = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-log-archive"])
    prod     = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-prod"])
    dev      = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-dev"])
  }
}

# =====================================================================
# 1. 管理を security アカウントに任せる(管理アカウントで行う)
# =====================================================================

# Config と IAM Access Analyzer は、Organizations の委任管理者の登録で任せる
resource "aws_organizations_delegated_administrator" "this" {
  for_each = toset([
    "config.amazonaws.com",
    "access-analyzer.amazonaws.com",
  ])

  account_id        = local.account_ids.security
  service_principal = each.key
}

# GuardDuty と Security Hub は、それぞれのサービスの API で任せる
resource "aws_guardduty_organization_admin_account" "this" {
  admin_account_id = local.account_ids.security
}

# Security Hub は、管理アカウントで有効にしてから任せる(AWS の手順)
resource "aws_securityhub_account" "management" {
  enable_default_standards = false
}

resource "aws_securityhub_organization_admin_account" "this" {
  admin_account_id = local.account_ids.security

  depends_on = [aws_securityhub_account.management]
}

# =====================================================================
# 2. GuardDuty(security アカウントで、組織全体を管理)
# =====================================================================

# security を委任管理者にすると、AWS が自動で検知器を作る。それを import して管理する
resource "aws_guardduty_detector" "security" {
  provider = aws.security
  enable   = true

  depends_on = [aws_guardduty_organization_admin_account.this]
}

# 組織のすべてのアカウント(今あるものも、これから増えるものも)で自動的に有効にする
resource "aws_guardduty_organization_configuration" "this" {
  provider                         = aws.security
  detector_id                      = aws_guardduty_detector.security.id
  auto_enable_organization_members = "ALL"
}

# 追加の保護プランは、組織でも security の検知器でも止めておく(費用を抑えるため)
resource "aws_guardduty_organization_configuration_feature" "optional" {
  for_each = toset(var.guardduty_optional_features)

  provider    = aws.security
  detector_id = aws_guardduty_detector.security.id
  name        = each.key
  auto_enable = "NONE"

  depends_on = [
    aws_guardduty_organization_configuration.this,
    aws_guardduty_detector.management,
  ]
}

resource "aws_guardduty_detector_feature" "optional" {
  for_each = toset(var.guardduty_optional_features)

  provider    = aws.security
  detector_id = aws_guardduty_detector.security.id
  name        = each.key
  status      = "DISABLED"
}

# =====================================================================
# 3. Security Hub CSPM(security アカウントで、組織全体を「一元設定」する)
# =====================================================================

# security を委任管理者にすると、AWS が自動で Security Hub を有効にする。それを import して管理する
resource "aws_securityhub_account" "security" {
  provider                 = aws.security
  enable_default_standards = false

  depends_on = [aws_securityhub_organization_admin_account.this]
}

# 一元設定を使うには、集約の設定(ホームリージョン)が必要。東京だけを使うので、他のリージョンはつながない
resource "aws_securityhub_finding_aggregator" "this" {
  provider     = aws.security
  linking_mode = "NO_REGIONS"

  depends_on = [aws_securityhub_account.security]
}

resource "aws_securityhub_organization_configuration" "this" {
  provider              = aws.security
  auto_enable           = false
  auto_enable_standards = "NONE"

  organization_configuration {
    configuration_type = "CENTRAL"
  }

  depends_on = [aws_securityhub_finding_aggregator.this]
}

# 組織全体のポリシー:Security Hub を有効にし、基準は「AWS 基礎セキュリティのベストプラクティス」だけ(DOC-03 7章)
resource "aws_securityhub_configuration_policy" "this" {
  provider    = aws.security
  name        = "${var.project}-baseline"
  description = "Enable Security Hub with AWS Foundational Security Best Practices only"

  configuration_policy {
    service_enabled = true
    enabled_standard_arns = [
      "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0",
    ]

    security_controls_configuration {
      disabled_control_identifiers = []
    }
  }

  depends_on = [aws_securityhub_organization_configuration.this]
}

resource "aws_securityhub_configuration_policy_association" "root" {
  provider  = aws.security
  target_id = local.root_id
  policy_id = aws_securityhub_configuration_policy.this.id
}

# =====================================================================
# 4. IAM Access Analyzer(security アカウントで、組織の外からのアクセスを分析)
# =====================================================================

# 組織の分析器を作るには、管理アカウントに Access Analyzer のサービスリンクロールが必要
resource "aws_iam_service_linked_role" "access_analyzer_management" {
  aws_service_name = "access-analyzer.amazonaws.com"
}

resource "aws_accessanalyzer_analyzer" "org" {
  provider      = aws.security
  analyzer_name = "${var.project}-org"
  type          = "ORGANIZATION"

  depends_on = [
    aws_organizations_delegated_administrator.this,
    aws_iam_service_linked_role.access_analyzer_management,
  ]
}

# =====================================================================
# 5. Config(全アカウントにレコーダー、security に組織のアグリゲーター)
# =====================================================================

module "config_management" {
  source         = "../modules/config-recorder"
  log_bucket     = local.log_bucket
  resource_types = var.config_resource_types
}

module "config_security" {
  source         = "../modules/config-recorder"
  providers      = { aws = aws.security }
  log_bucket     = local.log_bucket
  resource_types = var.config_resource_types
}

module "config_log" {
  source         = "../modules/config-recorder"
  providers      = { aws = aws.log }
  log_bucket     = local.log_bucket
  resource_types = var.config_resource_types
}

module "config_prod" {
  source         = "../modules/config-recorder"
  providers      = { aws = aws.prod }
  log_bucket     = local.log_bucket
  resource_types = var.config_resource_types
}

module "config_dev" {
  source         = "../modules/config-recorder"
  providers      = { aws = aws.dev }
  log_bucket     = local.log_bucket
  resource_types = var.config_resource_types
}

# アグリゲーター:全アカウントの Config の結果を security にまとめる
data "aws_iam_policy_document" "config_aggregator_trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "config_aggregator" {
  provider           = aws.security
  name               = "${var.project}-config-aggregator"
  description        = "Role for the organization-wide AWS Config aggregator"
  assume_role_policy = data.aws_iam_policy_document.config_aggregator_trust.json
}

resource "aws_iam_role_policy_attachment" "config_aggregator" {
  provider   = aws.security
  role       = aws_iam_role.config_aggregator.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRoleForOrganizations"
}

resource "aws_config_configuration_aggregator" "org" {
  provider = aws.security
  name     = "${var.project}-org"

  organization_aggregation_source {
    all_regions = false
    regions     = [var.aws_region]
    role_arn    = aws_iam_role.config_aggregator.arn
  }

  depends_on = [
    aws_organizations_delegated_administrator.this,
    aws_iam_role_policy_attachment.config_aggregator,
  ]
}

# 管理アカウントをメンバーにするには、先に管理アカウント自身で GuardDuty を有効にする必要がある(AWS の仕様)
resource "aws_guardduty_detector" "management" {
  #checkov:skip=CKV2_AWS_3:この検知器は aws_guardduty_member で security(委任管理者)の組織のメンバーにしている。Checkov はそのつながりを追えない
  enable = true
}

resource "aws_guardduty_detector_feature" "management_optional" {
  for_each = toset(var.guardduty_optional_features)

  detector_id = aws_guardduty_detector.management.id
  name        = each.key
  status      = "DISABLED"
}

# 既にあるアカウントは、auto_enable_organization_members = "ALL" だけでは
# メンバーにならなかった(検知器が作られなかった)。そのため、明示的にメンバーとして追加する。
# メールアドレスは Organizations の情報から取る(GuardDuty の API で必須のため)。
resource "aws_guardduty_member" "existing" {
  for_each = {
    for a in data.aws_organizations_organization.this.accounts : a.id => a.email
    if a.status == "ACTIVE" && a.id != local.account_ids.security
  }

  provider    = aws.security
  detector_id = aws_guardduty_detector.security.id
  account_id  = each.key
  email       = each.value
  invite      = false # 組織のアカウントなので招待は不要

  lifecycle {
    # email と invite は作成時だけの値で、作成後は読み取れない(違う値が返る)ため、差分を無視する
    ignore_changes = [email, invite]
  }

  depends_on = [
    aws_guardduty_organization_configuration.this,
    aws_guardduty_detector.management,
  ]
}
