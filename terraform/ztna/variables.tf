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

variable "cloudflare_account_id" {
  description = "Cloudflare のアカウントID(公開しない)"
  type        = string
  sensitive   = true
}

variable "domain" {
  description = "社内アプリに使うドメイン(Cloudflare で管理)"
  type        = string
  default     = "minato-kikaku-demo.com"
}

variable "admin_emails" {
  description = "P2-2a の動作確認で、メールのワンタイム PIN でサインインを許すメールアドレス(公開しない)"
  type        = list(string)
  sensitive   = true
}
