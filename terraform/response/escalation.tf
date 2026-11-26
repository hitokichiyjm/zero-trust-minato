# エスカレーション(FR-DB-03、UC-7、K-5、DOC-03 8.4。P2-4)
#   1時間ごとに escalate の Lambda(main.tf の functions)が、期限を過ぎたアラートを探し、
#   CRITICAL・HIGH は代表(このトピック)へ、MEDIUM は情報システム担当(いつもの通知のトピック)へ送る。
#   代表役のメールは、検証用の利用者と同じ Gmail の「+ceo」の別名(新しい Secret は作らず、TEST_EMAIL_BASE から組み立てる)。

locals {
  metric_namespace = "ZeroTrustMinato"
  email_parts      = split("@", var.test_email_base)
  ceo_email        = "${local.email_parts[0]}+ceo@${local.email_parts[1]}"
}

resource "aws_sns_topic" "escalation" {
  #checkov:skip=CKV_AWS_26:通知はメールで届くため、トピックを暗号化しても届く内容は平文になる。KMS の設定を増やさず単純にする(alerts と同じ)
  provider = aws.security
  name     = "${var.project}-escalation"
}

resource "aws_sns_topic_subscription" "escalation_ceo" {
  provider  = aws.security
  topic_arn = aws_sns_topic.escalation.arn
  protocol  = "email"
  endpoint  = local.ceo_email
}

# escalate だけの権限:検知を読む、escalatedAt を書く、代表のトピックに送る、⑧ を出す
data "aws_iam_policy_document" "lambda_escalate" {
  source_policy_documents = [data.aws_iam_policy_document.lambda_common.json]

  statement {
    sid       = "ReadAndMarkFindings"
    actions   = ["securityhub:GetFindings", "securityhub:BatchUpdateFindings"]
    resources = ["arn:aws:securityhub:${var.aws_region}:${local.security_id}:hub/default"]
  }

  statement {
    sid       = "PublishEscalation"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.escalation.arn]
  }

  statement {
    sid       = "PutOverdueMetric"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"] # PutMetricData はリソースを指定できない。名前空間の条件で絞る

    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = [local.metric_namespace]
    }
  }
}

resource "aws_cloudwatch_event_rule" "escalate" {
  provider            = aws.security
  name                = "${var.project}-escalate"
  description         = "Escalate overdue alerts every hour (P2-4)"
  schedule_expression = "rate(1 hour)"
}

resource "aws_cloudwatch_event_target" "escalate" {
  provider = aws.security
  rule     = aws_cloudwatch_event_rule.escalate.name
  arn      = aws_lambda_function.this["escalate"].arn
}

resource "aws_lambda_permission" "escalate_schedule" {
  provider      = aws.security
  statement_id  = "AllowHourlySchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this["escalate"].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.escalate.arn
}

# 失敗と停止のアラーム(security の中なので、通知のトピックに直接送る)
resource "aws_cloudwatch_metric_alarm" "escalate_errors" {
  provider            = aws.security
  alarm_name          = "${var.project}-escalate-errors"
  alarm_description   = "Escalation Lambda failed (P2-4). See DOC-04 OP-20"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.this["escalate"].function_name }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "escalate_not_running" {
  provider            = aws.security
  alarm_name          = "${var.project}-escalate-not-running"
  alarm_description   = "Escalation Lambda has not run for 3 hours (P2-4). See DOC-04 OP-20"
  namespace           = "AWS/Lambda"
  metric_name         = "Invocations"
  dimensions          = { FunctionName = aws_lambda_function.this["escalate"].function_name }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# 非同期の呼び出しの再試行はしない。再試行すると、送ったあとに失敗した場合に同じメールを2回送るおそれがある。
# 失敗はアラームで知らせ、次の1時間ごとの実行でやり直す
resource "aws_lambda_function_event_invoke_config" "escalate" {
  provider                     = aws.security
  function_name                = aws_lambda_function.this["escalate"].function_name
  maximum_retry_attempts       = 0
  maximum_event_age_in_seconds = 3600
}
