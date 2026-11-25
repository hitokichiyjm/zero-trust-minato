# すべてのアカウントにかける予防的な基本設定(FR-DT-08)と、CI が plan に使う読み取り専用ロール

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

variable "ci_plan_role_arn" {
  description = "このアカウントの読み取り専用ロールを引き受けてよい、CI(GitHub Actions)のロールの ARN。空なら作らない"
  type        = string
  default     = ""
}

# EC2 のインスタンスメタデータは IMDSv2(トークン必須)だけにする(TH-12:SSRF で認証情報を盗まれる対策)
resource "aws_ec2_instance_metadata_defaults" "this" {
  http_tokens                 = "required"
  http_put_response_hop_limit = 1
  http_endpoint               = "enabled"
}

# アカウント単位で S3 のパブリックアクセスをすべてブロックする(TH-18)
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# EBS のボリュームを必ず暗号化する
resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

# CI の plan 用の読み取り専用ロール(GitHub Actions の plan ロールからだけ引き受けられる)
data "aws_iam_policy_document" "ci_plan_trust" {
  count = var.ci_plan_role_arn == "" ? 0 : 1

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.ci_plan_role_arn]
    }
  }
}

resource "aws_iam_role" "ci_plan" {
  count = var.ci_plan_role_arn == "" ? 0 : 1

  name                 = "${var.project}-plan-readonly"
  description          = "Read-only role for terraform plan from CI"
  assume_role_policy   = data.aws_iam_policy_document.ci_plan_trust[0].json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "ci_plan" {
  count = var.ci_plan_role_arn == "" ? 0 : 1

  role       = aws_iam_role.ci_plan[0].name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# CI の plan 用ロールは ReadOnlyAccess で SSM の SecureString を復号して読めるため、
# Terraform で管理しない秘密(Cloudflare のログ用トークンなど。/<project>/cloudflare/ の下)は読めないようにする(P2-3 のレビュー H-1)
data "aws_iam_policy_document" "ci_plan_deny_secrets" {
  statement {
    sid    = "DenyUnmanagedSecrets"
    effect = "Deny"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParameterHistory",
    ]
    resources = ["arn:aws:ssm:*:*:parameter/${var.project}/cloudflare/*"]
  }

  # パスでまとめて読む操作は、上の階層(/<project> など)を指定すると下の秘密まで返すため、すべて禁止する
  # (Terraform の plan はこの操作を使わない)
  statement {
    sid       = "DenyReadByPath"
    effect    = "Deny"
    actions   = ["ssm:GetParametersByPath"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "ci_plan_deny_secrets" {
  count = var.ci_plan_role_arn == "" ? 0 : 1

  name   = "deny-unmanaged-secrets"
  role   = aws_iam_role.ci_plan[0].id
  policy = data.aws_iam_policy_document.ci_plan_deny_secrets.json
}
