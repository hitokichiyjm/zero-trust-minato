# ダッシュボード(DOC-03 10章、FR-DB-01・04、G-7。P2-4)
#   security アカウントに、3観点(リスク・脅威・対応状況)のダッシュボードと、指標を集める Lambda を置く。
#   指標は独自メトリクス(名前空間 ZeroTrustMinato、次元なし)で10個。⑧ はエスカレーションの Lambda(response)が出す。
#
#   集め方(どの API から、どの頻度で)
#     1時間ごと:① Security Hub のスコア ② Config の非準拠 ③ 長期のアクセスキー ④ GuardDuty の未対応 ⑦ 未対応のアラート ⑩ 対応までの時間
#     6時間ごと:⑤ Cloudflare で拒否 ⑥ サインインの失敗 ⑨ 自動対応(log-archive の Athena。logging スタックのロールを引き受ける)

data "aws_organizations_organization" "this" {}

locals {
  account_ids = {
    management = data.aws_organizations_organization.this.master_account_id
    security   = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-security"])
    log        = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-log-archive"])
    prod       = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-prod"])
    dev        = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-dev"])
  }

  namespace       = "ZeroTrustMinato"
  metrics_name    = "${var.project}-metrics" # baseline と logging が、このロールの名前を信頼の条件に使っている
  athena_role_arn = "arn:aws:iam::${local.account_ids.log}:role/${var.project}-metrics-athena"
  alerts_topic    = "arn:aws:sns:${var.aws_region}:${local.account_ids.security}:${var.project}-security-alerts" # response スタックのもの
}

data "archive_file" "metrics" {
  type        = "zip"
  source_dir  = "${path.module}/../../lambda/metrics"
  output_path = "${path.module}/.build/metrics.zip"
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

resource "aws_cloudwatch_log_group" "metrics" {
  provider = aws.security
  #checkov:skip=CKV_AWS_158:ログに秘密情報は出さない。KMS のキーの料金を抑えるため既定の暗号化を使う
  #checkov:skip=CKV_AWS_338:Lambda の動作ログは30日で十分(指標そのものは CloudWatch に残る)

  name              = "/aws/lambda/${local.metrics_name}"
  retention_in_days = var.lambda_log_retention_days
}

# 最小の権限:読むだけ(書くのは自分の指標とログだけ)
data "aws_iam_policy_document" "metrics" {
  statement {
    sid       = "ReadSecurityHub"
    actions   = ["securityhub:GetFindings"]
    resources = ["arn:aws:securityhub:${var.aws_region}:${local.account_ids.security}:hub/default"]
  }

  statement {
    sid       = "ReadConfigAggregator"
    actions   = ["config:DescribeAggregateComplianceByConfigRules"] # アグリゲーターの名前は環境変数で渡す(Describe は "*" が要るため使わない)
    resources = ["arn:aws:config:${var.aws_region}:${local.account_ids.security}:config-aggregator/*"]
  }

  statement {
    sid       = "ListGuardDutyDetectors"
    actions   = ["guardduty:ListDetectors"]
    resources = ["*"] # ListDetectors はリソースを指定できない
  }

  statement {
    sid       = "ReadGuardDutyFindings"
    actions   = ["guardduty:ListFindings"]
    resources = ["arn:aws:guardduty:${var.aws_region}:${local.account_ids.security}:detector/*"]
  }

  statement {
    sid     = "AssumeReaderRoles"
    actions = ["sts:AssumeRole"]
    resources = concat(
      [for id in values(local.account_ids) : "arn:aws:iam::${id}:role/${var.project}-metrics-reader"],
      [local.athena_role_arn],
    )
  }

  statement {
    sid       = "PutOwnMetrics"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"] # PutMetricData はリソースを指定できない。名前空間の条件で絞る

    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = [local.namespace]
    }
  }

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.metrics.arn}:*"]
  }
}

resource "aws_iam_role" "metrics" {
  provider           = aws.security
  name               = local.metrics_name
  description        = "Collect dashboard metrics (P2-4)"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy" "metrics" {
  provider = aws.security
  name     = "collect-metrics"
  role     = aws_iam_role.metrics.id
  policy   = data.aws_iam_policy_document.metrics.json
}

resource "aws_lambda_function" "metrics" {
  provider = aws.security
  #checkov:skip=CKV_AWS_116:スケジュールの呼び出しで、失敗しても次の回に同じ集計をやり直す。失敗は Errors のアラームで通知するため DLQ は要らない
  #checkov:skip=CKV_AWS_117:AWS の API だけに接続するため、VPC には置かない(NAT の費用がかかるため)
  #checkov:skip=CKV_AWS_173:環境変数に秘密情報は入れていない(アカウントID・ロール名・名前空間だけ)
  #checkov:skip=CKV_AWS_272:コードの署名は使わない(デプロイは Terraform と PR のレビューで管理する)
  #checkov:skip=CKV_AWS_115:新しいアカウントは同時実行数の上限が小さく、予約できないため
  #checkov:skip=CKV_AWS_50:X-Ray は使わない(処理が単純で、ログで追えるため)

  function_name    = local.metrics_name
  description      = "Collect the 10 dashboard metrics (P2-4)"
  role             = aws_iam_role.metrics.arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "handler.handler"
  filename         = data.archive_file.metrics.output_path
  source_code_hash = data.archive_file.metrics.output_base64sha256
  timeout          = 300
  memory_size      = 256

  environment {
    variables = {
      NAMESPACE             = local.namespace
      USE_SECURITY_HUB      = tostring(var.use_security_hub)
      ACCOUNT_IDS           = jsonencode(values(local.account_ids))
      READER_ROLE_NAME      = "${var.project}-metrics-reader"
      ATHENA_ROLE_ARN       = local.athena_role_arn
      ATHENA_WORKGROUP      = var.project
      ATHENA_DATABASE       = replace("${var.project}_logs", "-", "_")
      REMEDIATION_ROLE_NAME = "${var.project}-remediation"
      AGGREGATOR_NAME       = "${var.project}-org" # detection スタックのアグリゲーター
    }
  }

  depends_on = [aws_cloudwatch_log_group.metrics, aws_iam_role_policy.metrics]
}

# ---- スケジュール:1時間ごと(API)と、6時間ごと(Athena。費用を抑えるため) ----
locals {
  schedules = {
    hourly = { expression = "rate(1 hour)", group = "hourly" }
    athena = { expression = "rate(6 hours)", group = "athena" }
  }
}

resource "aws_cloudwatch_event_rule" "metrics" {
  for_each = local.schedules

  provider            = aws.security
  name                = "${local.metrics_name}-${each.key}"
  description         = "Collect dashboard metrics (${each.key})"
  schedule_expression = each.value.expression
}

resource "aws_cloudwatch_event_target" "metrics" {
  for_each = local.schedules

  provider = aws.security
  rule     = aws_cloudwatch_event_rule.metrics[each.key].name
  arn      = aws_lambda_function.metrics.arn
  input    = jsonencode({ group = each.value.group })
}

resource "aws_lambda_permission" "metrics" {
  for_each = local.schedules

  provider      = aws.security
  statement_id  = "AllowSchedule-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.metrics.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.metrics[each.key].arn
}

# ---- 失敗と停止のアラーム(security の通知のトピックに直接送る) ----
resource "aws_cloudwatch_metric_alarm" "metrics_errors" {
  provider            = aws.security
  alarm_name          = "${local.metrics_name}-errors"
  alarm_description   = "Dashboard metrics Lambda failed (P2-4). See DOC-04 OP-20"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.metrics.function_name }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [local.alerts_topic]
}

resource "aws_cloudwatch_metric_alarm" "metrics_not_running" {
  provider            = aws.security
  alarm_name          = "${local.metrics_name}-not-running"
  alarm_description   = "Dashboard metrics Lambda has not run for 3 hours (P2-4). See DOC-04 OP-20"
  namespace           = "AWS/Lambda"
  metric_name         = "Invocations"
  dimensions          = { FunctionName = aws_lambda_function.metrics.function_name }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [local.alerts_topic]
}

# 非同期の呼び出しの再試行はしない。同じ集計を繰り返すだけで、Athena の費用が増える。次の回でやり直す
resource "aws_lambda_function_event_invoke_config" "metrics" {
  provider                     = aws.security
  function_name                = aws_lambda_function.metrics.function_name
  maximum_retry_attempts       = 0
  maximum_event_age_in_seconds = 3600
}
