# GuardDuty の検知をログ用 S3 に保存する(DOC-03 9章の方法 B、FR-LG-01、P2-3)
#   security の既定のバス(委任管理者。メンバーの検知も集まる)
#     ─(転送)→ log-archive の受け取り用バス ─→ Lambda(log-archive)─→ ログ用 S3(guardduty/findings/)
#   GuardDuty の正式なエクスポートは顧客管理の KMS キー(月 1 USD)が必須のため使わない。
#   S3 への書き込みは log-archive の中だけで済み、ログ用 S3 のバケットポリシーを変えずに済む。

locals {
  gd_function = "${var.project}-guardduty-findings"
  gd_prefix   = "guardduty/findings"
  gd_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })
}

# ---- log-archive:受け取り用のバス(security の転送用ロールからだけ受け取る)----
resource "aws_cloudwatch_event_bus" "log_events" {
  provider = aws.log
  name     = "${var.project}-log-events"
}

data "aws_iam_policy_document" "log_events_bus" {
  statement {
    sid       = "AllowGuardDutyForwarderFromSecurity"
    actions   = ["events:PutEvents"]
    resources = [aws_cloudwatch_event_bus.log_events.arn]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.guardduty_forwarder.arn]
    }
  }
}

resource "aws_cloudwatch_event_bus_policy" "log_events" {
  provider       = aws.log
  event_bus_name = aws_cloudwatch_event_bus.log_events.name
  policy         = data.aws_iam_policy_document.log_events_bus.json
}

# ---- security:検知を log-archive のバスに転送する ----
# 信頼ポリシーは、この転送ルールからの引き受けだけに絞る(L-1)
data "aws_iam_policy_document" "events_trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.guardduty_forward.arn]
    }
  }
}

data "aws_iam_policy_document" "guardduty_forwarder" {
  statement {
    actions   = ["events:PutEvents"]
    resources = [aws_cloudwatch_event_bus.log_events.arn]
  }
}

resource "aws_iam_role" "guardduty_forwarder" {
  provider           = aws.security
  name               = "${var.project}-guardduty-to-log-archive"
  description        = "Forward GuardDuty findings to the log-archive event bus"
  assume_role_policy = data.aws_iam_policy_document.events_trust.json
}

resource "aws_iam_role_policy" "guardduty_forwarder" {
  provider = aws.security
  name     = "put-events"
  role     = aws_iam_role.guardduty_forwarder.id
  policy   = data.aws_iam_policy_document.guardduty_forwarder.json
}

resource "aws_cloudwatch_event_rule" "guardduty_forward" {
  provider      = aws.security
  name          = "${var.project}-guardduty-to-log-archive"
  description   = "Forward GuardDuty findings to log-archive for storage"
  event_pattern = local.gd_pattern
}

resource "aws_cloudwatch_event_target" "guardduty_forward" {
  provider = aws.security
  rule     = aws_cloudwatch_event_rule.guardduty_forward.name
  arn      = aws_cloudwatch_event_bus.log_events.arn
  role_arn = aws_iam_role.guardduty_forwarder.arn
}

# ---- log-archive:受け取って S3 に書く ----
data "archive_file" "guardduty_findings" {
  type        = "zip"
  source_dir  = "${path.module}/../../lambda/guardduty-findings"
  output_path = "${path.module}/.build/guardduty-findings.zip"
  excludes    = ["__pycache__"]
}

resource "aws_cloudwatch_log_group" "guardduty_findings" {
  provider = aws.log
  #checkov:skip=CKV_AWS_158:ログに秘密情報は出さない。KMS のキーの料金を抑えるため既定の暗号化を使う
  #checkov:skip=CKV_AWS_338:Lambda の動作ログは30日で十分(検知そのものは S3 に1年残る)

  name              = "/aws/lambda/${local.gd_function}"
  retention_in_days = var.lambda_log_retention_days
}

data "aws_iam_policy_document" "guardduty_findings" {
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.guardduty_findings.arn}:*"]
  }

  statement {
    sid       = "PutFindings"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/${local.gd_prefix}/*"]
  }
}

resource "aws_iam_role" "guardduty_findings" {
  provider           = aws.log
  name               = local.gd_function
  description        = "Store GuardDuty findings into the log bucket"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy" "guardduty_findings" {
  provider = aws.log
  name     = "store"
  role     = aws_iam_role.guardduty_findings.id
  policy   = data.aws_iam_policy_document.guardduty_findings.json
}

resource "aws_lambda_function" "guardduty_findings" {
  provider = aws.log
  #checkov:skip=CKV_AWS_116:非同期の呼び出しは Lambda が2回まで再試行する。それでも失敗したら Errors のアラームで通知する。検知そのものは GuardDuty(90日)と Security Hub にも残るため、DLQ は要らない
  #checkov:skip=CKV_AWS_117:AWS の API だけに接続するため、VPC には置かない(NAT の費用がかかるため)
  #checkov:skip=CKV_AWS_173:環境変数に秘密情報は入れていない
  #checkov:skip=CKV_AWS_272:コードの署名は使わない(デプロイは Terraform と PR のレビューで管理する)
  #checkov:skip=CKV_AWS_115:新しいアカウントは同時実行数の上限が小さく、予約できないため
  #checkov:skip=CKV_AWS_50:X-Ray は使わない(処理が単純で、ログで追えるため)

  function_name    = local.gd_function
  description      = "Store GuardDuty findings forwarded from the security account (P2-3)"
  role             = aws_iam_role.guardduty_findings.arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "handler.handler"
  filename         = data.archive_file.guardduty_findings.output_path
  source_code_hash = data.archive_file.guardduty_findings.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      LOG_BUCKET = aws_s3_bucket.logs.id
      PREFIX     = local.gd_prefix
    }
  }

  depends_on = [aws_cloudwatch_log_group.guardduty_findings, aws_iam_role_policy.guardduty_findings]
}

resource "aws_cloudwatch_event_rule" "guardduty_store" {
  provider       = aws.log
  name           = local.gd_function
  description    = "Store GuardDuty findings forwarded from the security account"
  event_bus_name = aws_cloudwatch_event_bus.log_events.name
  event_pattern  = local.gd_pattern
}

resource "aws_cloudwatch_event_target" "guardduty_store" {
  provider       = aws.log
  rule           = aws_cloudwatch_event_rule.guardduty_store.name
  event_bus_name = aws_cloudwatch_event_bus.log_events.name
  arn            = aws_lambda_function.guardduty_findings.arn
}

resource "aws_lambda_permission" "guardduty_findings" {
  provider      = aws.log
  statement_id  = "AllowLogEventsBus"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.guardduty_findings.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_store.arn
}
