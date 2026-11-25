# 通知と自動対応(DOC-03 8章)
#   各アカウントの操作イベント ─→ security の集約用バス ─→ 自動修復(AR-1)/ 通知(AR-2)
#   Security Hub の検知結果(security の既定のバス)─→ 通知(AR-3)

data "aws_organizations_organization" "this" {}
data "aws_caller_identity" "security" { provider = aws.security }

locals {
  org_id      = data.aws_organizations_organization.this.id
  security_id = data.aws_caller_identity.security.account_id

  account_ids = {
    security = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-security"])
    log      = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-log-archive"])
    prod     = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-prod"])
    dev      = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-dev"])
  }

  # AR-1(SG の全開放)と AR-2(ログ・検知を止める操作)のきっかけになる操作
  sg_event_names = ["AuthorizeSecurityGroupIngress"]
  stop_event_names = [
    "StopLogging", "DeleteTrail", "UpdateTrail",
    "DeleteDetector", "DisassociateFromAdministratorAccount", "DisassociateFromMasterAccount",
    "DisableSecurityHub",
    "StopConfigurationRecorder", "DeleteConfigurationRecorder", "DeleteDeliveryChannel",
    "DeleteAnalyzer",
  ]
}

# =====================================================================
# 1. 集約用のイベントバス(security)
# =====================================================================

resource "aws_cloudwatch_event_bus" "security" {
  provider = aws.security
  name     = "${var.project}-security-events"
}

# 組織のアカウントからだけ、イベントを受け取る
data "aws_iam_policy_document" "bus" {
  statement {
    sid       = "AllowPutEventsFromOrganization"
    actions   = ["events:PutEvents"]
    resources = [aws_cloudwatch_event_bus.security.arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [local.org_id]
    }
  }
}

resource "aws_cloudwatch_event_bus_policy" "security" {
  provider       = aws.security
  event_bus_name = aws_cloudwatch_event_bus.security.name
  policy         = data.aws_iam_policy_document.bus.json
}

# =====================================================================
# 2. 通知先(SNS:メール。Slack は Lambda から Webhook で送る)
# =====================================================================

resource "aws_sns_topic" "alerts" {
  #checkov:skip=CKV_AWS_26:通知はメールで届くため、トピックを暗号化しても届く内容は平文になる。KMS の設定を増やさず単純にする
  provider = aws.security
  name     = "${var.project}-security-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  provider  = aws.security
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# =====================================================================
# 3. Lambda(通知と自動修復)
# =====================================================================

data "archive_file" "response" {
  type        = "zip"
  source_dir  = "${path.module}/../../lambda/response"
  output_path = "${path.module}/.build/response.zip"
  excludes    = ["__pycache__"]
}

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

locals {
  slack_param_arn = "arn:aws:ssm:${var.aws_region}:${local.security_id}:parameter${var.slack_webhook_param}"

  functions = {
    notify = {
      handler     = "notify.handler"
      description = "Notify critical operations and high-severity findings (AR-2, AR-3)"
    }
    remediate-sg = {
      handler     = "remediate_sg.handler"
      description = "Revoke security group rules open to the internet on risky ports (AR-1)"
    }
  }
}

# 共通の権限:ログを書く、SNS に送る、Slack の URL を読む
data "aws_iam_policy_document" "lambda_common" {
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [for k, _ in local.functions : "${aws_cloudwatch_log_group.lambda[k].arn}:*"]
  }

  statement {
    sid       = "PublishAlerts"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid       = "ReadSlackWebhook"
    actions   = ["ssm:GetParameter"]
    resources = [local.slack_param_arn]
  }
}

# 通知だけの権限:検知結果のワークフローの状態を NOTIFIED にする
data "aws_iam_policy_document" "lambda_notify" {
  source_policy_documents = [data.aws_iam_policy_document.lambda_common.json]

  statement {
    sid       = "MarkFindingsNotified"
    actions   = ["securityhub:BatchUpdateFindings"]
    resources = ["arn:aws:securityhub:${var.aws_region}:${local.security_id}:hub/default"]
  }
}

# 自動修復だけの権限:各アカウントの修復用ロールを引き受ける
data "aws_iam_policy_document" "lambda_remediate" {
  source_policy_documents = [data.aws_iam_policy_document.lambda_common.json]

  statement {
    sid       = "AssumeRemediationRoles"
    actions   = ["sts:AssumeRole"]
    resources = ["arn:aws:iam::*:role/${var.project}-remediation"]
  }
}

resource "aws_iam_role" "lambda" {
  for_each = local.functions

  provider           = aws.security
  name               = "${var.project}-${each.key}"
  description        = each.value.description
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy" "lambda" {
  for_each = local.functions

  provider = aws.security
  name     = "permissions"
  role     = aws_iam_role.lambda[each.key].id
  policy   = each.key == "notify" ? data.aws_iam_policy_document.lambda_notify.json : data.aws_iam_policy_document.lambda_remediate.json
}

resource "aws_cloudwatch_log_group" "lambda" {
  for_each = local.functions
  #checkov:skip=CKV_AWS_158:ログに秘密情報は出さない。KMS のキーの料金を抑えるため既定の暗号化を使う
  #checkov:skip=CKV_AWS_338:Lambda の動作ログは30日で十分(操作の記録は CloudTrail で1年保管している)

  provider          = aws.security
  name              = "/aws/lambda/${var.project}-${each.key}"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "this" {
  for_each = local.functions
  #checkov:skip=CKV_AWS_116:失敗したイベントは CloudWatch Logs で追える。DLQ は P2 で検討する
  #checkov:skip=CKV_AWS_117:AWS の API と Slack だけに接続するため、VPC には置かない(NAT の費用がかかるため)
  #checkov:skip=CKV_AWS_173:環境変数に秘密情報は入れていない(Slack の URL は SSM から読む)
  #checkov:skip=CKV_AWS_272:コードの署名は使わない(デプロイは Terraform と PR のレビューで管理する)
  #checkov:skip=CKV_AWS_115:新しいアカウントは同時実行数の上限が小さく、予約できないため
  #checkov:skip=CKV_AWS_50:X-Ray は使わない(処理が単純で、ログで追えるため)

  provider         = aws.security
  function_name    = "${var.project}-${each.key}"
  description      = each.value.description
  role             = aws_iam_role.lambda[each.key].arn
  runtime          = "python3.13"
  handler          = each.value.handler
  filename         = data.archive_file.response.output_path
  source_code_hash = data.archive_file.response.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      SNS_TOPIC_ARN         = aws_sns_topic.alerts.arn
      SLACK_WEBHOOK_PARAM   = var.slack_webhook_param
      REMEDIATION_ROLE_NAME = "${var.project}-remediation"
      RISKY_PORTS           = join(",", var.risky_ports)
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda, aws_iam_role_policy.lambda]
}

# =====================================================================
# 4. ルール(どのイベントを、どの Lambda に渡すか)
# =====================================================================

locals {
  rules = {
    # AR-1:SG の変更(集約用バス)→ 自動修復
    sg-ingress = {
      bus      = aws_cloudwatch_event_bus.security.name
      function = "remediate-sg"
      pattern = {
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail        = { eventName = local.sg_event_names }
      }
    }
    # AR-2:ログ・検知を止める操作(集約用バス)→ 通知
    stop-security = {
      bus      = aws_cloudwatch_event_bus.security.name
      function = "notify"
      pattern = {
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail        = { eventName = local.stop_event_names }
      }
    }
    # AR-2:ルートユーザーのサインイン(集約用バス)→ 通知
    root-sign-in = {
      bus      = aws_cloudwatch_event_bus.security.name
      function = "notify"
      pattern = {
        "detail-type" = ["AWS Console Sign In via CloudTrail"]
        detail        = { userIdentity = { type = ["Root"] } }
      }
    }
    # P2-3:ログの収集用の Lambda(log-archive)の失敗のアラーム(集約用バス。logging スタックが転送する)→ 通知
    collector-alarm = {
      bus      = aws_cloudwatch_event_bus.security.name
      function = "notify"
      pattern = {
        source        = ["aws.cloudwatch"]
        "detail-type" = ["CloudWatch Alarm State Change"]
        detail        = { state = { value = ["ALARM"] } }
      }
    }
    # AR-3:Security Hub の重大度 HIGH 以上で、まだ通知していないもの(security の既定のバス)→ 通知
    high-findings = {
      bus      = "default"
      function = "notify"
      pattern = {
        source        = ["aws.securityhub"]
        "detail-type" = ["Security Hub Findings - Imported"]
        detail = {
          findings = {
            Severity    = { Label = ["HIGH", "CRITICAL"] }
            Workflow    = { Status = ["NEW"] }
            RecordState = ["ACTIVE"]
          }
        }
      }
    }
  }
}

resource "aws_cloudwatch_event_rule" "this" {
  for_each = local.rules

  provider       = aws.security
  name           = "${var.project}-${each.key}"
  event_bus_name = each.value.bus
  event_pattern  = jsonencode(each.value.pattern)
}

resource "aws_cloudwatch_event_target" "this" {
  for_each = local.rules

  provider       = aws.security
  rule           = aws_cloudwatch_event_rule.this[each.key].name
  event_bus_name = each.value.bus
  arn            = aws_lambda_function.this[each.value.function].arn
}

resource "aws_lambda_permission" "events" {
  for_each = local.rules

  provider      = aws.security
  statement_id  = "AllowEventBridge-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this[each.value.function].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.this[each.key].arn
}

# =====================================================================
# 5. 各アカウントからの転送と、修復用ロール
# =====================================================================

locals {
  forward_event_names = concat(local.sg_event_names, local.stop_event_names)
  remediator_arn      = aws_iam_role.lambda["remediate-sg"].arn
}

module "forward_management" {
  source          = "../modules/event-forwarder"
  project         = var.project
  target_bus_arn  = aws_cloudwatch_event_bus.security.arn
  api_event_names = local.forward_event_names
}

module "forward_management_us_east_1" {
  source               = "../modules/event-forwarder"
  providers            = { aws = aws.management_us_east_1 }
  project              = var.project
  target_bus_arn       = aws_cloudwatch_event_bus.security.arn
  forward_api_calls    = false
  forward_root_sign_in = true
}

module "forward_security" {
  source                    = "../modules/event-forwarder"
  providers                 = { aws = aws.security }
  project                   = var.project
  target_bus_arn            = aws_cloudwatch_event_bus.security.arn
  api_event_names           = local.forward_event_names
  create_remediation_role   = true
  remediation_principal_arn = local.remediator_arn
}

module "forward_log" {
  source                    = "../modules/event-forwarder"
  providers                 = { aws = aws.log }
  project                   = var.project
  target_bus_arn            = aws_cloudwatch_event_bus.security.arn
  api_event_names           = local.forward_event_names
  create_remediation_role   = true
  remediation_principal_arn = local.remediator_arn
}

module "forward_prod" {
  source                    = "../modules/event-forwarder"
  providers                 = { aws = aws.prod }
  project                   = var.project
  target_bus_arn            = aws_cloudwatch_event_bus.security.arn
  api_event_names           = local.forward_event_names
  create_remediation_role   = true
  remediation_principal_arn = local.remediator_arn
}

module "forward_dev" {
  source                    = "../modules/event-forwarder"
  providers                 = { aws = aws.dev }
  project                   = var.project
  target_bus_arn            = aws_cloudwatch_event_bus.security.arn
  api_event_names           = local.forward_event_names
  create_remediation_role   = true
  remediation_principal_arn = local.remediator_arn
}
