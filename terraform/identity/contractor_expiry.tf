# 外部委託者の期限切れ(FR-ID-06、UC-2、DOC-03 5.3。P2-4)
#   毎日 0:10(日本時間)に Lambda(管理アカウント)が動き、契約の終了日(expires)を過ぎた外部委託者を g-contractor から外す。
#   外れると、AWS の権限も ZTNA のポリシー(SAML の groups)も失う。Identity Center の利用者そのものは消さない。
#   外したら、security の集約用バスにイベントを送り、既存の通知(notify → メール)で知らせる。
#   Cloudflare のセッションの取り消しは手作業(DOC-04 OP-12 → OP-11 の手順2)。

locals {
  expiry_function = "${var.project}-contractor-expiry"

  # 期限のある人(今は外部委託者だけ)。名前・ID・期限を Lambda に渡す(秘密ではない。メールは渡さない)
  contractors = {
    for k, v in local.test_users : k => {
      user_id = aws_identitystore_user.test[k].user_id
      expires = v.expires
    } if try(v.expires, null) != null
  }

  identity_store_arn = "arn:aws:identitystore::${local.account_ids.management}:identitystore/${local.identity_store_id}"
  security_bus_arn   = "arn:aws:events:${var.aws_region}:${local.account_ids.security}:event-bus/${var.project}-security-events"
}

data "archive_file" "contractor_expiry" {
  type        = "zip"
  source_dir  = "${path.module}/../../lambda/contractor-expiry"
  output_path = "${path.module}/.build/contractor-expiry.zip"
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

resource "aws_cloudwatch_log_group" "contractor_expiry" {
  #checkov:skip=CKV_AWS_158:ログに秘密情報は出さない。KMS のキーの料金を抑えるため既定の暗号化を使う
  #checkov:skip=CKV_AWS_338:Lambda の動作ログは30日で十分(所属の削除そのものは CloudTrail に1年残る)

  name              = "/aws/lambda/${local.expiry_function}"
  retention_in_days = var.lambda_log_retention_days
}

# 最小の権限:g-contractor のグループの、期限のある人の所属だけを調べて消せる。
#   DeleteGroupMembership と GetGroupMembershipId は、ID ストア・グループ・利用者・所属の4つのリソースをすべて求める
#   (サービス認可リファレンス)。グループを g-contractor だけ、利用者を期限のある人だけにして、ほかのグループや人には効かないようにする。
#   所属の ID は事前に分からないため membership/* になる。
data "aws_iam_policy_document" "contractor_expiry" {
  statement {
    sid     = "RemoveExpiredContractorsFromContractorGroupOnly"
    actions = ["identitystore:GetGroupMembershipId", "identitystore:DeleteGroupMembership"]
    resources = concat(
      [
        local.identity_store_arn,
        "arn:aws:identitystore:::group/${aws_identitystore_group.this["g-contractor"].group_id}",
        "arn:aws:identitystore:::membership/*",
      ],
      [for c in values(local.contractors) : "arn:aws:identitystore:::user/${c.user_id}"],
    )

    # 条件でも、期限のある人の ID だけに絞る(identitystore:UserId。グループの ID の条件キーはない)。
    # サービス認可リファレンスでは、この2つの操作の条件キーの欄に UserId が載っていない(PrimaryRegion だけ)。
    # 要求にキーがないと StringEquals は常に合わず、外せなくなるため、IfExists にする(キーがあるときだけ絞る)。
    # 主な絞り込みは、上のリソース(グループと利用者の ARN)で行う
    condition {
      test     = "StringEqualsIfExists"
      variable = "identitystore:UserId"
      values   = [for c in values(local.contractors) : c.user_id]
    }
  }

  statement {
    sid       = "NotifyViaSecurityBus"
    actions   = ["events:PutEvents"]
    resources = [local.security_bus_arn]
  }

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.contractor_expiry.arn}:*"]
  }
}

resource "aws_iam_role" "contractor_expiry" {
  name               = local.expiry_function
  description        = "Remove expired contractors from g-contractor (P2-4, FR-ID-06)"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy" "contractor_expiry" {
  name   = "remove-expired"
  role   = aws_iam_role.contractor_expiry.id
  policy = data.aws_iam_policy_document.contractor_expiry.json
}

resource "aws_lambda_function" "contractor_expiry" {
  #checkov:skip=CKV_AWS_116:スケジュールの呼び出しで、失敗しても次の日に同じ判定をやり直す。失敗は Errors のアラームで通知するため DLQ は要らない
  #checkov:skip=CKV_AWS_117:AWS の API だけに接続するため、VPC には置かない(NAT の費用がかかるため)
  #checkov:skip=CKV_AWS_173:環境変数に秘密情報は入れていない(利用者名・利用者の ID・期限・グループの ID だけ)
  #checkov:skip=CKV_AWS_272:コードの署名は使わない(デプロイは Terraform と PR のレビューで管理する)
  #checkov:skip=CKV_AWS_115:新しいアカウントは同時実行数の上限が小さく、予約できないため
  #checkov:skip=CKV_AWS_50:X-Ray は使わない(処理が単純で、ログで追えるため)

  function_name    = local.expiry_function
  description      = "Remove expired contractors from g-contractor daily (P2-4, FR-ID-06)"
  role             = aws_iam_role.contractor_expiry.arn
  runtime          = "python3.13"
  architectures    = ["arm64"]
  handler          = "handler.handler"
  filename         = data.archive_file.contractor_expiry.output_path
  source_code_hash = data.archive_file.contractor_expiry.output_base64sha256
  timeout          = 60
  memory_size      = 128

  environment {
    variables = {
      IDENTITY_STORE_ID = local.identity_store_id
      GROUP_ID          = aws_identitystore_group.this["g-contractor"].group_id
      GROUP_NAME        = "g-contractor"
      CONTRACTORS       = jsonencode(local.contractors)
      EVENT_BUS_ARN     = local.security_bus_arn
      EVENT_SOURCE      = "${var.project}.identity"
    }
  }

  depends_on = [aws_cloudwatch_log_group.contractor_expiry, aws_iam_role_policy.contractor_expiry]
}

# 非同期の呼び出しの再試行は、既定のまま(2回)にする。外す処理は何度やっても同じ結果になり(冪等)、
# 1日1回なので、一時的な失敗で次の日まで外れないほうが困るため
resource "aws_lambda_function_event_invoke_config" "contractor_expiry" {
  function_name                = aws_lambda_function.contractor_expiry.function_name
  maximum_retry_attempts       = 2
  maximum_event_age_in_seconds = 21600
}

# 毎日 0:10(日本時間)= 15:10(UTC)
resource "aws_cloudwatch_event_rule" "contractor_expiry" {
  name                = local.expiry_function
  description         = "Remove expired contractors daily at 00:10 JST"
  schedule_expression = "cron(10 15 * * ? *)"
}

resource "aws_cloudwatch_event_target" "contractor_expiry" {
  rule = aws_cloudwatch_event_rule.contractor_expiry.name
  arn  = aws_lambda_function.contractor_expiry.arn
}

resource "aws_lambda_permission" "contractor_expiry" {
  statement_id  = "AllowDailySchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.contractor_expiry.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.contractor_expiry.arn
}

# 失敗したら、集約用バスに知らせる手段がないので(Lambda そのものが失敗しているため)、アラームの状態の変化を
# 管理アカウントの既定のバスから集約用バスに転送する(logging の収集用の Lambda と同じ形)
resource "aws_cloudwatch_metric_alarm" "contractor_expiry_errors" {
  alarm_name          = "${var.project}-contractor-expiry-errors"
  alarm_description   = "Contractor expiry Lambda failed (P2-4). See DOC-04 OP-12"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.contractor_expiry.function_name }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_event_rule" "contractor_expiry_alarm" {
  name        = "${var.project}-forward-contractor-expiry-alarm"
  description = "Forward the contractor expiry alarm to the security account"
  event_pattern = jsonencode({
    source        = ["aws.cloudwatch"]
    "detail-type" = ["CloudWatch Alarm State Change"]
    detail = {
      alarmName = [aws_cloudwatch_metric_alarm.contractor_expiry_errors.alarm_name]
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
      values   = [aws_cloudwatch_event_rule.contractor_expiry_alarm.arn]
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
  name               = "${var.project}-contractor-expiry-alarm-forwarder"
  description        = "Forward the contractor expiry alarm to the security account event bus"
  assume_role_policy = data.aws_iam_policy_document.alarm_forwarder_trust.json
}

resource "aws_iam_role_policy" "alarm_forwarder" {
  name   = "put-events"
  role   = aws_iam_role.alarm_forwarder.id
  policy = data.aws_iam_policy_document.alarm_forwarder.json
}

resource "aws_cloudwatch_event_target" "contractor_expiry_alarm" {
  rule     = aws_cloudwatch_event_rule.contractor_expiry_alarm.name
  arn      = local.security_bus_arn
  role_arn = aws_iam_role.alarm_forwarder.arn
}
