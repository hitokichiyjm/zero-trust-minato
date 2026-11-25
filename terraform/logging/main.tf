# ログの集約(DOC-03 9章)
# - 組織の CloudTrail(管理アカウントで作る)
# - ログ用 S3(log-archive アカウント):オブジェクトロックで、保持期間中は消せない・書き換えられない

data "aws_organizations_organization" "this" {}
data "aws_caller_identity" "management" {}
data "aws_partition" "current" {}

locals {
  org_id        = data.aws_organizations_organization.this.id
  management_id = data.aws_caller_identity.management.account_id
  log_id        = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-log-archive"])
  security_id   = one([for a in data.aws_organizations_organization.this.accounts : a.id if a.name == "${var.project}-security"])

  # 組織の全アカウント(Config の書き込みを許す相手)
  org_account_ids = sort([for a in data.aws_organizations_organization.this.accounts : a.id if a.status == "ACTIVE"])

  trail_name = "${var.project}-org-trail"
  trail_arn  = "arn:${data.aws_partition.current.partition}:cloudtrail:${var.aws_region}:${local.management_id}:trail/${local.trail_name}"
}

# ---- ログ用 S3(log-archive アカウント) ----
resource "random_id" "logs_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "logs" {
  provider = aws.log
  #checkov:skip=CKV_AWS_144:別リージョンへの複製は行わない。東京だけで運用する前提(DOC-01 9章)
  #checkov:skip=CKV_AWS_145:SSE-S3 で暗号化する。KMS のキーの料金を抑えるため(DOC-03 9.1)
  #checkov:skip=CKV_AWS_18:ログ用バケット自身のアクセスログは取らない(CloudTrail で操作を記録している)
  #checkov:skip=CKV2_AWS_62:イベント通知は使わない

  # 名前は SCP の protect-logs(zero-trust-minato-logs-*)に合わせる
  bucket              = "${var.project}-logs-${random_id.logs_suffix.hex}"
  object_lock_enabled = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  provider = aws.log
  bucket   = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# オブジェクトロック:保持期間中は、誰もログを消したり書き換えたりできない(FR-LG-02、TH-21)
# GOVERNANCE モードは特別な権限(s3:BypassGovernanceRetention)があれば解除できるが、
# その権限は SCP の protect-logs で禁止している(例外は Terraform 用のロールだけ)。
# COMPLIANCE モードはルートユーザーでも解除できないため、ポートフォリオを片付けられなくなる。そのため GOVERNANCE を選ぶ。
resource "aws_s3_bucket_object_lock_configuration" "logs" {
  provider = aws.log
  bucket   = aws_s3_bucket.logs.id

  rule {
    default_retention {
      mode = var.object_lock_mode
      days = var.log_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.logs]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  provider = aws.log
  bucket   = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  provider = aws.log
  bucket   = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  provider = aws.log
  bucket   = aws_s3_bucket.logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# 保管期間(NFR-LOG-02:1年)を過ぎたら消す。
# CloudTrail のログは1つが小さく、低頻度アクセス用のストレージ(最小 128KB 課金)に移すとかえって高くなるため、移さない
resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  provider = aws.log
  bucket   = aws_s3_bucket.logs.id

  rule {
    id     = "expire-after-retention"
    status = "Enabled"

    filter {}

    expiration {
      days = var.log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 1
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.logs]
}

# 書き込めるのは CloudTrail(この組織の証跡だけ)。暗号化されていない通信は拒否する
# Config は、オブジェクトロックのあるバケットに書き込めないため、別のバケットに送る(config.tf)
data "aws_iam_policy_document" "logs" {
  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.logs.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid     = "CloudTrailWrite"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.logs.arn}/AWSLogs/${local.management_id}/*",
      "${aws_s3_bucket.logs.arn}/AWSLogs/${local.org_id}/*",
    ]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.logs.arn,
      "${aws_s3_bucket.logs.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  provider = aws.log
  bucket   = aws_s3_bucket.logs.id
  policy   = data.aws_iam_policy_document.logs.json

  depends_on = [aws_s3_bucket_public_access_block.logs]
}

# ---- 組織の CloudTrail(管理アカウント) ----
resource "aws_cloudtrail" "org" {
  #checkov:skip=CKV_AWS_35:ログは SSE-S3 で暗号化する。KMS のキーの料金を抑えるため(DOC-03 9.1)
  #checkov:skip=CKV_AWS_252:SNS への通知は使わない(検知と通知は GuardDuty と EventBridge で行う)
  #checkov:skip=CKV2_AWS_10:CloudWatch Logs への送信は、費用を抑えるため P1 では行わない(検索は S3 から行う)

  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.logs.id
  is_organization_trail         = true
  is_multi_region_trail         = true # SCP で禁止したリージョンでの操作の「試み」も記録する
  include_global_service_events = true # IAM、STS、Identity Center のサインインなど
  enable_log_file_validation    = true # ログファイルが書き換えられていないかを検証できるようにする

  depends_on = [aws_s3_bucket_policy.logs]
}
