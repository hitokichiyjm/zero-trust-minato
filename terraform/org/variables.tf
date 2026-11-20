variable "project" {
  description = "リソース名とタグに使うプロジェクト名"
  type        = string
  default     = "zero-trust-minato"
}

variable "aws_region" {
  description = "基本のリージョン。SCP で、これ以外のリージョンの利用を禁止する"
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

variable "account_emails" {
  description = "各アカウントのルートユーザーのメールアドレス(security, log, prod, dev)"
  type        = map(string)
  sensitive   = true

  validation {
    condition     = alltrue([for k in ["security", "log", "prod", "dev"] : contains(keys(var.account_emails), k)])
    error_message = "security, log, prod, dev の4つを指定してください。"
  }
}

variable "extra_service_access_principals" {
  description = "組織が既に信頼しているサービスのうち、このコードの一覧にないもの(消さないために残す)"
  type        = list(string)
  default     = []
}
