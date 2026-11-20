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

variable "log_retention_days" {
  description = "ログの保管期間(日)。オブジェクトロックの保持期間と、削除までの期間に使う(NFR-LOG-02)"
  type        = number
  default     = 365
}

variable "object_lock_mode" {
  description = "オブジェクトロックのモード。GOVERNANCE(特別な権限で解除できる)か COMPLIANCE(誰も解除できない)"
  type        = string
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.object_lock_mode)
    error_message = "GOVERNANCE か COMPLIANCE を指定してください。"
  }
}
