variable "project" {
  description = "リソース名とタグに使うプロジェクト名"
  type        = string
  default     = "zero-trust-minato"
}

variable "aws_region" {
  description = "基本のリージョン"
  type        = string
  default     = "ap-northeast-1"
}

variable "management_account_id" {
  description = "管理アカウントのID"
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.management_account_id))
    error_message = "12桁の数字で指定してください。"
  }
}

variable "member_role_name" {
  description = "メンバーアカウントで引き受けるロールの名前。手元は OrganizationAccountAccessRole、CI は zero-trust-minato-plan-readonly"
  type        = string
  default     = "OrganizationAccountAccessRole"
}

variable "lambda_log_retention_days" {
  description = "Lambda の動作ログ(CloudWatch Logs)の保持期間(日)"
  type        = number
  default     = 30
}

variable "use_security_hub" {
  description = "Security Hub を使う指標(①⑦⑩)を集めるか。無料トライアルの後に Security Hub を止めたら false にする(DOC-03 10章、D-1)"
  type        = bool
  default     = true
}
