output "tfstate_bucket" {
  description = "状態ファイル用の S3 バケット名(backend.hcl と GitHub の Secret TF_STATE_BUCKET に使う)"
  value       = aws_s3_bucket.tfstate.bucket
}

output "github_plan_role_arn" {
  description = "GitHub Actions が使うロールの ARN(GitHub の Secret AWS_PLAN_ROLE_ARN に使う)"
  value       = aws_iam_role.github_plan.arn
}
