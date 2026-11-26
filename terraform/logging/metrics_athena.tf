# ダッシュボードの指標⑤⑥⑨を Athena で集計するためのロール(P2-4、DOC-03 10章)
#   security の集計用 Lambda(dashboard スタック)が引き受け、log-archive の Athena で検索する。
#   読めるのは、CloudTrail と Cloudflare のログのプレフィックスと、検索結果のバケットだけ。

locals {
  metrics_principal_arn = "arn:${data.aws_partition.current.partition}:iam::${local.security_id}:role/${var.project}-metrics"
}

data "aws_iam_policy_document" "metrics_athena_trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${local.security_id}:root"]
    }

    # 集計用 Lambda のロールだけ(ロールを直接書くと、先にそのロールがないと作れないため条件で絞る)
    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [local.metrics_principal_arn]
    }
  }
}

data "aws_iam_policy_document" "metrics_athena" {
  statement {
    sid       = "RunQueriesInWorkgroup"
    actions   = ["athena:StartQueryExecution", "athena:GetQueryExecution", "athena:GetQueryResults", "athena:StopQueryExecution", "athena:GetWorkGroup"]
    resources = [aws_athena_workgroup.this.arn]
  }

  statement {
    sid     = "ReadCatalog"
    actions = ["glue:GetDatabase", "glue:GetTable", "glue:GetPartitions"]
    resources = [
      "arn:${data.aws_partition.current.partition}:glue:${var.aws_region}:${local.log_id}:catalog",
      "arn:${data.aws_partition.current.partition}:glue:${var.aws_region}:${local.log_id}:database/${aws_glue_catalog_database.logs.name}",
      "arn:${data.aws_partition.current.partition}:glue:${var.aws_region}:${local.log_id}:table/${aws_glue_catalog_database.logs.name}/*",
    ]
  }

  statement {
    sid     = "ReadLogs"
    actions = ["s3:GetObject"]
    resources = [
      "${aws_s3_bucket.logs.arn}/AWSLogs/${local.org_id}/*",
      "${aws_s3_bucket.logs.arn}/${local.cloudflare_prefix}/*",
    ]
  }

  statement {
    sid       = "ListLogs"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
    resources = [aws_s3_bucket.logs.arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["AWSLogs/${local.org_id}/*", "${local.cloudflare_prefix}/*"]
    }
  }

  statement {
    sid       = "BucketLocation"
    actions   = ["s3:GetBucketLocation"]
    resources = [aws_s3_bucket.logs.arn, aws_s3_bucket.athena_results.arn]
  }

  statement {
    sid       = "WriteResults"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
    resources = ["${aws_s3_bucket.athena_results.arn}/results/*"]
  }

  statement {
    sid       = "ListResults"
    actions   = ["s3:ListBucket", "s3:ListBucketMultipartUploads"]
    resources = [aws_s3_bucket.athena_results.arn]
  }
}

resource "aws_iam_role" "metrics_athena" {
  provider             = aws.log
  name                 = "${var.project}-metrics-athena"
  description          = "Run dashboard queries in Athena from the security account (P2-4)"
  assume_role_policy   = data.aws_iam_policy_document.metrics_athena_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "metrics_athena" {
  provider = aws.log
  name     = "athena-queries"
  role     = aws_iam_role.metrics_athena.id
  policy   = data.aws_iam_policy_document.metrics_athena.json
}
