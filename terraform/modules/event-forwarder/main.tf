# 各アカウントの操作イベントを、security アカウントの集約用バスに転送する。
# あわせて、security の自動修復の Lambda が引き受ける「修復用ロール」を作る(必要なアカウントだけ)。

terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

variable "project" {
  type = string
}

variable "target_bus_arn" {
  description = "転送先(security アカウントの集約用バス)の ARN"
  type        = string
}

variable "forward_api_calls" {
  description = "CloudTrail の操作イベント(SG の変更、検知の停止など)を転送するか"
  type        = bool
  default     = true
}

variable "api_event_names" {
  description = "転送する CloudTrail の操作の名前"
  type        = list(string)
  default     = []
}

variable "forward_root_sign_in" {
  description = "ルートユーザーのコンソールへのサインインを転送するか"
  type        = bool
  default     = true
}

variable "create_remediation_role" {
  description = "修復用ロールを作るか(plan の時点で決まる値にするため、ARN とは別に指定する)"
  type        = bool
  default     = false
}

variable "remediation_principal_arn" {
  description = "修復用ロールを引き受けてよい、security の Lambda のロールの ARN"
  type        = string
  default     = ""
}

# ---- 転送 ----
data "aws_iam_policy_document" "events_trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "put_events" {
  statement {
    actions   = ["events:PutEvents"]
    resources = [var.target_bus_arn]
  }
}

data "aws_region" "current" {}

resource "aws_iam_role" "forwarder" {
  # IAM はグローバルなので、リージョンごとに名前を分ける
  name               = "${var.project}-event-forwarder-${data.aws_region.current.region}"
  description        = "Forward security events to the security account event bus"
  assume_role_policy = data.aws_iam_policy_document.events_trust.json
}

resource "aws_iam_role_policy" "forwarder" {
  name   = "put-events"
  role   = aws_iam_role.forwarder.id
  policy = data.aws_iam_policy_document.put_events.json
}

resource "aws_cloudwatch_event_rule" "api_calls" {
  count = var.forward_api_calls ? 1 : 0

  name        = "${var.project}-forward-api-calls"
  description = "Forward risky API calls to the security account"
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = var.api_event_names
    }
  })
}

resource "aws_cloudwatch_event_target" "api_calls" {
  count = var.forward_api_calls ? 1 : 0

  rule     = aws_cloudwatch_event_rule.api_calls[0].name
  arn      = var.target_bus_arn
  role_arn = aws_iam_role.forwarder.arn
}

resource "aws_cloudwatch_event_rule" "root_sign_in" {
  count = var.forward_root_sign_in ? 1 : 0

  name        = "${var.project}-forward-root-sign-in"
  description = "Forward root user console sign-in to the security account"
  event_pattern = jsonencode({
    "detail-type" = ["AWS Console Sign In via CloudTrail"]
    detail = {
      userIdentity = {
        type = ["Root"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "root_sign_in" {
  count = var.forward_root_sign_in ? 1 : 0

  rule     = aws_cloudwatch_event_rule.root_sign_in[0].name
  arn      = var.target_bus_arn
  role_arn = aws_iam_role.forwarder.arn
}

# ---- 修復用ロール(security の Lambda だけが引き受けられる。SG のルールを消すことだけができる) ----
data "aws_iam_policy_document" "remediation_trust" {
  count = var.create_remediation_role ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.remediation_principal_arn]
    }
  }
}

data "aws_iam_policy_document" "remediation" {
  count = var.create_remediation_role ? 1 : 0

  statement {
    sid = "ReadSecurityGroups"
    actions = [
      "ec2:DescribeSecurityGroupRules",
      "ec2:DescribeSecurityGroups",
    ]
    # Describe 系はリソースを指定できない(AWS の仕様)
    resources = ["*"]
  }

  statement {
    sid       = "RevokeIngressOnly"
    actions   = ["ec2:RevokeSecurityGroupIngress"]
    resources = ["arn:aws:ec2:*:*:security-group/*"]
  }
}

resource "aws_iam_role" "remediation" {
  count = var.create_remediation_role ? 1 : 0

  name               = "${var.project}-remediation"
  description        = "Assumed by the security account to revoke risky security group rules"
  assume_role_policy = data.aws_iam_policy_document.remediation_trust[0].json
}

resource "aws_iam_role_policy" "remediation" {
  count = var.create_remediation_role ? 1 : 0

  name   = "revoke-security-group-ingress"
  role   = aws_iam_role.remediation[0].id
  policy = data.aws_iam_policy_document.remediation[0].json
}
