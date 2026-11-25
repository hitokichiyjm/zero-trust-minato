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

# ---- P2-3:検索と、Cloudflare・GuardDuty のログの収集 ----
variable "cloudflare_account_id" {
  description = "Cloudflare のアカウントID(Access のログを取る Lambda が使う。公開しない)"
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.cloudflare_account_id))
    error_message = "32桁の16進数で指定してください。"
  }
}

variable "cloudtrail_query_start" {
  description = "Athena の CloudTrail のテーブルで、パーティション射影を始める日(yyyy/MM/dd)。組織の証跡を作った日より前にする"
  type        = string
  default     = "2026/11/01"

  validation {
    condition     = can(regex("^[0-9]{4}/[0-9]{2}/[0-9]{2}$", var.cloudtrail_query_start))
    error_message = "yyyy/MM/dd の形で指定してください。"
  }
}

variable "cloudflare_logs_start" {
  description = "Athena の Cloudflare のログのテーブルで、パーティション射影を始める日(yyyy-MM-dd)"
  type        = string
  default     = "2026-11-25"

  validation {
    condition     = can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", var.cloudflare_logs_start))
    error_message = "yyyy-MM-dd の形で指定してください。"
  }
}

variable "lambda_log_retention_days" {
  description = "Lambda の動作ログ(CloudWatch Logs)の保持期間(日)"
  type        = number
  default     = 30
}

variable "athena_results_retention_days" {
  description = "Athena の検索結果を残す日数"
  type        = number
  default     = 7
}

variable "athena_bytes_scanned_cutoff" {
  description = "Athena の1回の検索で読む量の上限(バイト)。費用の上限(既定は 1 GB)"
  type        = number
  default     = 1073741824
}
