output "account_ids" {
  description = "メンバーアカウントのID(他のスタックで使う。公開しない)"
  value       = { for k, a in aws_organizations_account.this : k => a.id }
  sensitive   = true
}

output "ou_ids" {
  description = "OU の ID"
  value       = local.ou_ids
}
