# Terraform の状態ファイルを置く S3 バケット(NFR-SEC-03, NFR-SEC-04)
# バケット名にアカウントIDを入れず、ランダムな文字列を付ける(公開リポジトリにIDを出さないため)

resource "random_id" "state_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "tfstate" {
  #checkov:skip=CKV_AWS_144:別リージョンへの複製は、費用を優先して行わない(バージョニングで復旧できる)
  #checkov:skip=CKV_AWS_145:SSE-S3 で暗号化する。KMS のキーの料金を抑えるため(DOC-03 9.1 と同じ方針)
  #checkov:skip=CKV_AWS_18:アクセスログは CloudTrail(P1 の組織の証跡)で代わりに取る
  #checkov:skip=CKV2_AWS_62:状態ファイルの変更を通知する必要はない
  bucket = "${var.project}-tfstate-${random_id.state_suffix.hex}"

  # 誤って消さないように
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    id     = "expire-old-versions"
    status = "Enabled"

    filter {}

    # 古い版の状態ファイルは90日で消す(それまでは戻せる)
    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.tfstate]
}

# 暗号化されていない通信(HTTP)を拒否する
data "aws_iam_policy_document" "tfstate" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.tfstate.arn,
      "${aws_s3_bucket.tfstate.arn}/*",
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

resource "aws_s3_bucket_policy" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  policy = data.aws_iam_policy_document.tfstate.json

  depends_on = [aws_s3_bucket_public_access_block.tfstate]
}
