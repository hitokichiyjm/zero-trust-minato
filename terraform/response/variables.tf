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

variable "notification_email" {
  description = "通知を送るメールアドレス(SNS)。登録後に届く確認メールのリンクを押す必要がある"
  type        = string
  sensitive   = true
}

variable "slack_webhook_param" {
  description = "Slack の Webhook URL を入れる SSM Parameter Store の名前(security アカウント)。値は手で登録する(秘密情報のため Terraform では扱わない)"
  type        = string
  default     = "/zero-trust-minato/slack-webhook-url"
}

variable "risky_ports" {
  description = "インターネット全体に開けてはいけないポート(AR-1)"
  type        = list(number)
  default     = [21, 22, 23, 445, 1433, 3306, 3389, 5432, 6379, 9200, 27017]
}

variable "log_retention_days" {
  description = "Lambda のログの保管期間(日)"
  type        = number
  default     = 30
}

variable "test_email_base" {
  description = "検証用の利用者と同じ Gmail のアドレス。「+ceo」を付けて、代表役のエスカレーションの宛先にする(公開しない。CI は Secret の TEST_EMAIL_BASE)"
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[^@+]+@[^@]+$", var.test_email_base))
    error_message = "「+」を含まないメールアドレスで指定してください。"
  }
}

variable "escalation_start" {
  description = "エスカレーションを始めた日(日本時間、YYYY-MM-DD)。これより前に見つかった検知は送らず、⑧ にも数えない(DOC-03 8.4)"
  type        = string
  default     = "2026-11-26"

  validation {
    condition     = can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", var.escalation_start))
    error_message = "YYYY-MM-DD の形で指定してください。"
  }
}
