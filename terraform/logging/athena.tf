# ログの検索(DOC-03 9.2、P2-3)
#   log-archive アカウントの Athena で、ログ用 S3 の CloudTrail と Cloudflare Access のログを検索する。
#   テーブルはパーティション射影を使う(クローラーを動かさず、日付のパーティションを自動で決める)。

data "aws_regions" "enabled" {}

locals {
  athena_db = replace("${var.project}_logs", "-", "_")

  # 組織の証跡のログの置き場所:AWSLogs/<組織ID>/<アカウントID>/CloudTrail/<リージョン>/yyyy/MM/dd/
  cloudtrail_root = "s3://${aws_s3_bucket.logs.id}/AWSLogs/${local.org_id}"

  # Cloudflare Access のログの置き場所(cloudflare_logs.tf の Lambda が書く)
  cloudflare_prefix = "cloudflare/access_requests"
}

# ---- 検索結果のバケット(log-archive) ----
# 名前は zero-trust-minato-logs-* にしない(SCP の protect-logs の対象にすると、ライフサイクルの変更などができなくなる)
resource "random_id" "athena_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "athena_results" {
  provider = aws.log
  # 下の skip は、手元の Checkov(3.4.5)では対象にならなかった(暗号化などを別のリソースで設定しているため)。
  # CI の Checkov の版で出る場合に備えて、理由とともに残す(P2-3)
  #checkov:skip=CKV_AWS_144:別リージョンへの複製は行わない。検索結果は一時的なもの
  #checkov:skip=CKV_AWS_145:SSE-S3 で暗号化する。KMS のキーの料金を抑えるため(DOC-03 9.1)
  #checkov:skip=CKV_AWS_18:検索結果のバケットのアクセスログは取らない(Athena の操作は CloudTrail に残る)
  #checkov:skip=CKV_AWS_21:検索結果は7日で消す一時的なもの。バージョニングは要らない
  #checkov:skip=CKV2_AWS_62:イベント通知は使わない

  bucket = "${var.project}-athena-results-${random_id.athena_suffix.hex}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results" {
  provider = aws.log
  bucket   = aws_s3_bucket.athena_results.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  provider = aws.log
  bucket   = aws_s3_bucket.athena_results.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "athena_results" {
  provider = aws.log
  bucket   = aws_s3_bucket.athena_results.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  provider = aws.log
  bucket   = aws_s3_bucket.athena_results.id

  rule {
    id     = "expire-results"
    status = "Enabled"
    filter {}

    expiration {
      days = var.athena_results_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

data "aws_iam_policy_document" "athena_results" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.athena_results.arn,
      "${aws_s3_bucket.athena_results.arn}/*",
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

resource "aws_s3_bucket_policy" "athena_results" {
  provider = aws.log
  bucket   = aws_s3_bucket.athena_results.id
  policy   = data.aws_iam_policy_document.athena_results.json

  depends_on = [aws_s3_bucket_public_access_block.athena_results]
}

# ---- ワークグループ:結果の置き場所と暗号化を強制し、1回の検索で読む量に上限を付ける ----
resource "aws_athena_workgroup" "this" {
  provider = aws.log
  name     = var.project

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    bytes_scanned_cutoff_per_query     = var.athena_bytes_scanned_cutoff

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.id}/results/"

      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}

resource "aws_glue_catalog_database" "logs" {
  provider    = aws.log
  name        = local.athena_db
  description = "Log search (CloudTrail, Cloudflare Access)"
}

# ---- CloudTrail のテーブル(AWS の公式の例を、組織の証跡の形に広げたもの) ----
# https://docs.aws.amazon.com/athena/latest/ug/create-cloudtrail-table-partition-projection.html
resource "aws_glue_catalog_table" "cloudtrail" {
  provider      = aws.log
  name          = "cloudtrail"
  database_name = aws_glue_catalog_database.logs.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"                    = "TRUE"
    "classification"              = "cloudtrail"
    "projection.enabled"          = "true"
    "projection.account.type"     = "enum"
    "projection.account.values"   = join(",", local.org_account_ids)
    "projection.region.type"      = "enum"
    "projection.region.values"    = join(",", sort(tolist(data.aws_regions.enabled.names)))
    "projection.dt.type"          = "date"
    "projection.dt.format"        = "yyyy/MM/dd"
    "projection.dt.range"         = "${var.cloudtrail_query_start},NOW"
    "projection.dt.interval"      = "1"
    "projection.dt.interval.unit" = "DAYS"
    "storage.location.template"   = "${local.cloudtrail_root}/$${account}/CloudTrail/$${region}/$${dt}"
  }

  partition_keys {
    name = "account"
    type = "string"
  }
  partition_keys {
    name = "region"
    type = "string"
  }
  partition_keys {
    name = "dt"
    type = "string"
  }

  storage_descriptor {
    location      = "${local.cloudtrail_root}/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hive.hcatalog.data.JsonSerDe"
    }

    columns {
      name = "eventversion"
      type = "string"
    }
    columns {
      name = "useridentity"
      type = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,onbehalfof:struct<userid:string,identitystorearn:string>,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>,ec2roledelivery:string,webidfederationdata:struct<federatedprovider:string,attributes:map<string,string>>>>"
    }
    dynamic "columns" {
      for_each = [
        "eventtime", "eventsource", "eventname", "awsregion", "sourceipaddress", "useragent",
        "errorcode", "errormessage", "requestparameters", "responseelements", "additionaleventdata",
        "requestid", "eventid", "readonly",
      ]
      content {
        name = columns.value
        type = "string"
      }
    }
    columns {
      name = "resources"
      type = "array<struct<arn:string,accountid:string,type:string>>"
    }
    dynamic "columns" {
      for_each = [
        "eventtype", "apiversion", "recipientaccountid", "serviceeventdetails", "sharedeventid",
        "vpcendpointid", "vpcendpointaccountid", "eventcategory",
      ]
      content {
        name = columns.value
        type = "string"
      }
    }
    columns {
      name = "addendum"
      type = "struct<reason:string,updatedfields:string,originalrequestid:string,originaleventid:string>"
    }
    columns {
      name = "sessioncredentialfromconsole"
      type = "string"
    }
    columns {
      name = "edgedevicedetails"
      type = "string"
    }
    columns {
      name = "tlsdetails"
      type = "struct<tlsversion:string,ciphersuite:string,clientprovidedhostheader:string>"
    }
  }
}

# ---- Cloudflare Access のログのテーブル(JSON Lines、gzip。dt=yyyy-MM-dd のパーティション射影) ----
resource "aws_glue_catalog_table" "cloudflare_access" {
  provider      = aws.log
  name          = "cloudflare_access_requests"
  database_name = aws_glue_catalog_database.logs.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"                    = "TRUE"
    "classification"              = "json"
    "projection.enabled"          = "true"
    "projection.dt.type"          = "date"
    "projection.dt.format"        = "yyyy-MM-dd"
    "projection.dt.range"         = "${var.cloudflare_logs_start},NOW"
    "projection.dt.interval"      = "1"
    "projection.dt.interval.unit" = "DAYS"
    "storage.location.template"   = "s3://${aws_s3_bucket.logs.id}/${local.cloudflare_prefix}/dt=$${dt}"
  }

  partition_keys {
    name = "dt"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.logs.id}/${local.cloudflare_prefix}/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
    }

    # API の access_requests の項目(Cloudflare の API のスキーマ)
    dynamic "columns" {
      for_each = {
        action     = "string"
        allowed    = "boolean"
        app_domain = "string"
        app_uid    = "string"
        connection = "string"
        created_at = "string"
        ip_address = "string"
        ray_id     = "string"
        user_email = "string"
      }
      content {
        name = columns.key
        type = columns.value
      }
    }
  }
}

# ---- 保存する検索(OP-50 の月次の振り返りで使う)----
# 日付の条件(dt)を必ず入れて、読む量を抑える。利用者の名前などは「?」にして、実行のときに入れる
locals {
  ct  = "\"${local.athena_db}\".\"cloudtrail\""
  cf  = "\"${local.athena_db}\".\"cloudflare_access_requests\""
  d7  = "dt >= date_format(current_date - interval '7' day, '%Y/%m/%d')"
  d30 = "dt >= date_format(current_date - interval '30' day, '%Y/%m/%d')"

  named_queries = {
    "01-user-activity-7d" = {
      description = "ある利用者の直近7日の操作とサインイン(? に利用者名の一部を入れる)"
      # Identity Center の利用者のサインイン(useridentity.type = IdentityCenterUser)は arn に名前が入らないため、
      # username と additionaleventdata・serviceeventdetails も見る(2026-11-25 に実際のログで確かめた)
      query = <<-SQL
        WITH p AS (SELECT concat('%', ?, '%') AS pat)
        SELECT eventtime, account, useridentity.type, eventsource, eventname, errorcode, sourceipaddress, useridentity.arn
        FROM ${local.ct} CROSS JOIN p
        WHERE ${local.d7}
          AND (useridentity.arn LIKE p.pat
               OR useridentity.username LIKE p.pat
               OR additionaleventdata LIKE p.pat
               OR serviceeventdetails LIKE p.pat)
        ORDER BY eventtime DESC
        LIMIT 500
      SQL
    }
    "02-root-usage-30d" = {
      description = "ルートユーザーの利用(直近30日)"
      query       = <<-SQL
        SELECT eventtime, account, eventsource, eventname, errorcode, sourceipaddress
        FROM ${local.ct}
        WHERE ${local.d30}
          AND useridentity.type = 'Root'
          AND eventtype <> 'AwsServiceEvent'
        ORDER BY eventtime DESC
      SQL
    }
    "03-security-group-changes-30d" = {
      description = "セキュリティグループの変更(直近30日。AR-1 の自動修復も含む)"
      query       = <<-SQL
        SELECT eventtime, account, eventname, errorcode, useridentity.arn, requestparameters
        FROM ${local.ct}
        WHERE ${local.d30}
          AND eventsource = 'ec2.amazonaws.com'
          AND eventname IN ('AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress',
                            'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress',
                            'ModifySecurityGroupRules', 'CreateSecurityGroup', 'DeleteSecurityGroup')
        ORDER BY eventtime DESC
      SQL
    }
    "04-identity-center-sign-in-failures-7d" = {
      description = "Identity Center のサインインの失敗(直近7日。ダッシュボードの⑥の元)"
      query       = <<-SQL
        SELECT eventtime, eventname, errorcode, errormessage, sourceipaddress, serviceeventdetails, additionaleventdata
        FROM ${local.ct}
        WHERE ${local.d7}
          AND eventsource IN ('signin.amazonaws.com', 'sso.amazonaws.com')
          AND eventname IN ('CredentialVerification', 'CredentialChallenge', 'UserAuthentication', 'Federate')
          AND (errorcode IS NOT NULL OR serviceeventdetails LIKE '%Failure%')
        ORDER BY eventtime DESC
      SQL
    }
    "05-access-denied-7d" = {
      description = "権限で拒否された操作(SCP・IAM。直近7日)"
      query       = <<-SQL
        SELECT account, eventsource, eventname, errorcode, useridentity.arn, count(*) AS n, max(eventtime) AS last_time
        FROM ${local.ct}
        WHERE ${local.d7}
          AND (errorcode LIKE '%AccessDenied%' OR errorcode LIKE '%UnauthorizedOperation%')
        GROUP BY account, eventsource, eventname, errorcode, useridentity.arn
        ORDER BY n DESC
        LIMIT 200
      SQL
    }
    "06-cloudflare-access-denied-30d" = {
      description = "Cloudflare Access で拒否した数(日ごと・アプリごと。直近30日。ダッシュボードの⑤の元)"
      query       = <<-SQL
        SELECT dt, app_domain, count(DISTINCT ray_id) AS denied
        FROM ${local.cf}
        WHERE dt >= date_format(current_date - interval '30' day, '%Y-%m-%d')
          AND allowed = false
        GROUP BY dt, app_domain
        ORDER BY dt DESC, denied DESC
      SQL
    }
  }
}

resource "aws_athena_named_query" "this" {
  for_each = local.named_queries

  provider    = aws.log
  name        = each.key
  description = each.value.description
  workgroup   = aws_athena_workgroup.this.id
  database    = aws_glue_catalog_database.logs.name
  query       = each.value.query
}
