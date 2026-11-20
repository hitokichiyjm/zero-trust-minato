# Config の配信先(log-archive アカウント)
#
# CloudTrail のログ用バケット(オブジェクトロックあり)には、Config が書き込めなかった
# (InsufficientDeliveryPolicyException)。オブジェクトロックの既定の保持期間があるバケットへのアップロードには
# Content-MD5 などのチェックサムが必須で、Config の書き込みの試験がそれを満たさないためと考えられる。
# そのため、Config は別のバケットに送る。
# - 名前を zero-trust-minato-logs-* にして、SCP の protect-logs で削除・ポリシーの変更から守る
# - オブジェクトロックの代わりに、バージョニングで上書き・削除から戻せるようにする

resource "aws_s3_bucket" "config" {
  provider = aws.log
  #checkov:skip=CKV_AWS_144:別リージョンへの複製は行わない。東京だけで運用する前提(DOC-01 9章)
  #checkov:skip=CKV_AWS_145:SSE-S3 で暗号化する。KMS のキーの料金を抑えるため(DOC-03 9.1)
  #checkov:skip=CKV_AWS_18:アクセスログは取らない(CloudTrail で操作を記録している)
  #checkov:skip=CKV2_AWS_62:イベント通知は使わない

  bucket = "${var.project}-logs-config-${random_id.logs_suffix.hex}"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "config" {
  provider = aws.log
  bucket   = aws_s3_bucket.config.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  provider = aws.log
  bucket   = aws_s3_bucket.config.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  provider = aws.log
  bucket   = aws_s3_bucket.config.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "config" {
  provider = aws.log
  bucket   = aws_s3_bucket.config.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "config" {
  provider = aws.log
  bucket   = aws_s3_bucket.config.id

  rule {
    id     = "expire-after-retention"
    status = "Enabled"

    filter {}

    expiration {
      days = var.log_retention_days
    }

    # 上書き・削除された古い版は、30日間は戻せるようにする
    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.config]
}

# AWS のドキュメントどおり、Config のサービスプリンシパルに、組織のアカウントからの書き込みだけを許す
data "aws_iam_policy_document" "config" {
  statement {
    sid       = "AWSConfigBucketPermissionsCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config.arn]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = local.org_account_ids
    }
  }

  statement {
    sid       = "AWSConfigBucketExistenceCheck"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.config.arn]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = local.org_account_ids
    }
  }

  statement {
    sid       = "AWSConfigBucketDelivery"
    actions   = ["s3:PutObject"]
    resources = [for id in local.org_account_ids : "${aws_s3_bucket.config.arn}/AWSLogs/${id}/Config/*"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = local.org_account_ids
    }
  }

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.config.arn,
      "${aws_s3_bucket.config.arn}/*",
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

resource "aws_s3_bucket_policy" "config" {
  provider = aws.log
  bucket   = aws_s3_bucket.config.id
  policy   = data.aws_iam_policy_document.config.json

  depends_on = [aws_s3_bucket_public_access_block.config]
}

output "config_bucket" {
  description = "Config の配信先のバケット名(detection スタックで使う。公開しない)"
  value       = aws_s3_bucket.config.id
  sensitive   = true
}
