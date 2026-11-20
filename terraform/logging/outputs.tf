output "log_bucket" {
  description = "ログ用 S3 のバケット名(detection スタックの Config で使う。公開しない)"
  value       = aws_s3_bucket.logs.id
  sensitive   = true
}

output "org_trail_arn" {
  description = "組織の CloudTrail の ARN"
  value       = aws_cloudtrail.org.arn
  sensitive   = true
}
