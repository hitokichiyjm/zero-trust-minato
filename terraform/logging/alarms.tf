# 収集用の Lambda の失敗を、既存の通知(response の notify → SNS → メール)で知らせる(P2-3 のレビュー M-1)
#   CloudWatch のアラーム(log-archive)─ 状態の変化のイベント ─→ log-archive の既定のバス
#     ─(転送)→ security の集約用バス(response スタック)─→ notify の Lambda ─→ SNS
#   アラームの通知先に、別アカウント(security)の SNS を直接は使わない。既にある集約用バスと notify を使い回す。

locals {
  # response スタックで作った集約用バス(組織のアカウントから PutEvents を受け付ける)
  security_bus_arn = "arn:${data.aws_partition.current.partition}:events:${var.aws_region}:${local.security_id}:event-bus/${var.project}-security-events"

  collector_functions = {
    cloudflare-logs    = aws_lambda_function.cloudflare_logs.function_name
    guardduty-findings = aws_lambda_function.guardduty_findings.function_name
  }
}

resource "aws_cloudwatch_metric_alarm" "collector_errors" {
  for_each = local.collector_functions

  provider            = aws.log
  alarm_name          = "${var.project}-${each.key}-errors"
  alarm_description   = "Log collector Lambda failed (P2-3). See DOC-04 OP-20"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = each.value }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
}

# ---- アラームになったことを security の集約用バスに転送する ----
resource "aws_cloudwatch_event_rule" "collector_alarm" {
  provider    = aws.log
  name        = "${var.project}-forward-collector-alarms"
  description = "Forward log collector alarms to the security account"
  event_pattern = jsonencode({
    source        = ["aws.cloudwatch"]
    "detail-type" = ["CloudWatch Alarm State Change"]
    detail = {
      alarmName = [for k, _ in local.collector_functions : "${var.project}-${k}-errors"]
      state     = { value = ["ALARM"] }
    }
  })
}

data "aws_iam_policy_document" "alarm_forwarder_trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.collector_alarm.arn]
    }
  }
}

data "aws_iam_policy_document" "alarm_forwarder" {
  statement {
    actions   = ["events:PutEvents"]
    resources = [local.security_bus_arn]
  }
}

resource "aws_iam_role" "alarm_forwarder" {
  provider           = aws.log
  name               = "${var.project}-collector-alarm-forwarder"
  description        = "Forward log collector alarms to the security account event bus"
  assume_role_policy = data.aws_iam_policy_document.alarm_forwarder_trust.json
}

resource "aws_iam_role_policy" "alarm_forwarder" {
  provider = aws.log
  name     = "put-events"
  role     = aws_iam_role.alarm_forwarder.id
  policy   = data.aws_iam_policy_document.alarm_forwarder.json
}

resource "aws_cloudwatch_event_target" "collector_alarm" {
  provider = aws.log
  rule     = aws_cloudwatch_event_rule.collector_alarm.name
  arn      = local.security_bus_arn
  role_arn = aws_iam_role.alarm_forwarder.arn
}
