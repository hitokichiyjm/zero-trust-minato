# Cloudflare Access の認証のログを集める(DOC-03 9章、FR-AC-05、FR-LG-01、P2-3)
#   EventBridge(6時間ごと)→ Lambda(log-archive)→ Cloudflare の API → ログ用 S3(cloudflare/access_requests/)
#   Free プランでは Cloudflare に24時間しか残らないため、6時間ごとに直近24時間分を取る
#   (3回失敗しても取りこぼさない。重なった分は Athena で ray_id で重複を除く)。

locals {
  cf_function = "${var.project}-cloudflare-logs"

  # トークンの SSM パラメーター(SecureString)は、Terraform では管理しない。利用者が CLI で作る・上書きする
  # (docs/build/P2_完成形.md の P2-3、DOC-04 OP-47)。
  # Terraform で管理すると、ignore_changes を付けても refresh のたびに本物の値が state に書かれるため(2026-11-26 に発覚)。
  # IAM と Lambda には、名前から組み立てた ARN と名前だけを渡す(data "aws_ssm_parameter" も値を state に入れるので使わない)。
  cf_token_param     = "/${var.project}/cloudflare/access-logs-token"
  cf_token_param_arn = "arn:${data.aws_partition.current.partition}:ssm:${var.aws_region}:${local.log_id}:parameter${local.cf_token_param}"
}

# 2026-11-26:Terraform の管理から外す。パラメーターそのものは消さない(destroy = false)
removed {
  from = aws_ssm_parameter.cloudflare_logs_token

  lifecycle {
    destroy = false
  }
}

data "archive_file" "cloudflare_logs" {
  type        = "zip"
  source_dir  = "${path.module}/../../lambda/cloudflare-logs"
  output_path = "${path.module}/.build/cloudflare-logs.zip"
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

resource "aws_cloudwatch_log_group" "cloudflare_logs" {
  provider = aws.log
  #checkov:skip=CKV_AWS_158:ログに秘密情報は出さない。KMS のキーの料金を抑えるため既定の暗号化を使う
  #checkov:skip=CKV_AWS_338:Lambda の動作ログは30日で十分(集めたログそのものは S3 に1年残る)

  name              = "/aws/lambda/${local.cf_function}"
  retention_in_days = var.lambda_log_retention_days
}

# 最小の権限:自分のログを書く、トークンを読む、決まった場所にだけ書く
data "aws_iam_policy_document" "cloudflare_logs" {
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.cloudflare_logs.arn}:*"]
  }

  statement {
    sid       = "ReadToken"
    actions   = ["ssm:GetParameter"]
    resources = [local.cf_token_param_arn]
  }

  statement {
    sid       = "PutAccessLogs"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/${local.cloudflare_prefix}/*"]
  }
}

resource "aws_iam_role" "cloudflare_logs" {
  provider           = aws.log
  name               = local.cf_function
  description        = "Collect Cloudflare Access logs into the log bucket"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy" "cloudflare_logs" {
  provider = aws.log
  name     = "collect"
  role     = aws_iam_role.cloudflare_logs.id
  policy   = data.aws_iam_policy_document.cloudflare_logs.json
}

resource "aws_lambda_function" "cloudflare_logs" {
  provider = aws.log
  #checkov:skip=CKV_AWS_116:スケジュールの呼び出しは再試行で同じ期間を取り直すだけ。失敗は Errors のアラームで通知し、次の実行で24時間分を取り直すため DLQ は要らない
  #checkov:skip=CKV_AWS_117:Cloudflare の API と AWS の API だけに接続するため、VPC には置かない(NAT の費用がかかるため)
  #checkov:skip=CKV_AWS_173:環境変数に秘密情報は入れていない(トークンは SSM から読む。Cloudflare のアカウントIDは秘密ではないが公開しない値)
  #checkov:skip=CKV_AWS_272:コードの署名は使わない(デプロイは Terraform と PR のレビューで管理する)
  #checkov:skip=CKV_AWS_115:新しいアカウントは同時実行数の上限が小さく、予約できないため
  #checkov:skip=CKV_AWS_50:X-Ray は使わない(処理が単純で、ログで追えるため)

  function_name    = local.cf_function
  description      = "Collect Cloudflare Access authentication logs (last 24h) every 6 hours (P2-3)"
  role             = aws_iam_role.cloudflare_logs.arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "handler.handler"
  filename         = data.archive_file.cloudflare_logs.output_path
  source_code_hash = data.archive_file.cloudflare_logs.output_base64sha256
  timeout          = 120
  memory_size      = 128

  environment {
    variables = {
      TOKEN_PARAM           = local.cf_token_param
      CLOUDFLARE_ACCOUNT_ID = var.cloudflare_account_id
      LOG_BUCKET            = aws_s3_bucket.logs.id
      PREFIX                = local.cloudflare_prefix
      WINDOW_HOURS          = "24"
    }
  }

  depends_on = [aws_cloudwatch_log_group.cloudflare_logs, aws_iam_role_policy.cloudflare_logs]
}

resource "aws_cloudwatch_event_rule" "cloudflare_logs" {
  provider            = aws.log
  name                = local.cf_function
  description         = "Collect Cloudflare Access logs every 6 hours"
  schedule_expression = "rate(6 hours)"
}

resource "aws_cloudwatch_event_target" "cloudflare_logs" {
  provider = aws.log
  rule     = aws_cloudwatch_event_rule.cloudflare_logs.name
  arn      = aws_lambda_function.cloudflare_logs.arn
}

resource "aws_lambda_permission" "cloudflare_logs" {
  provider      = aws.log
  statement_id  = "AllowSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cloudflare_logs.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cloudflare_logs.arn
}
