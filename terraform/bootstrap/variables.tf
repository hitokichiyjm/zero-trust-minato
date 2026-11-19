variable "project" {
  description = "リソース名とタグに使うプロジェクト名"
  type        = string
  default     = "zero-trust-minato"
}

variable "aws_region" {
  description = "基本のリージョン(DOC-01 9章)"
  type        = string
  default     = "ap-northeast-1"
}

variable "management_account_id" {
  description = "管理アカウントのID。間違ったアカウントへの適用を防ぐために使う"
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.management_account_id))
    error_message = "12桁の数字で指定してください。"
  }
}

variable "github_repository" {
  description = "OIDC で AWS に入れる GitHub のリポジトリ(owner/repo の形)"
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "owner/repo の形で指定してください。"
  }
}

variable "github_owner_id" {
  description = "GitHub のリポジトリの持ち主のID(数字)。gh api users/<owner> --jq .id で確認できる"
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.github_owner_id))
    error_message = "数字で指定してください。"
  }
}

variable "github_repository_id" {
  description = "GitHub のリポジトリのID(数字)。gh api repos/<owner>/<repo> --jq .id で確認できる"
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.github_repository_id))
    error_message = "数字で指定してください。"
  }
}

variable "notification_email" {
  description = "費用アラートの送り先"
  type        = string
  sensitive   = true
}

# ---- 費用アラート(NFR-COST-02) ----
# Budgets は USD で設定する。1 USD = 150円で計算し、
# 上限 5,000円 ≒ 33 USD、予測の通知 3,000円 ≒ 20 USD(33 USD の 60%)。
variable "budget_limit_usd" {
  description = "月の予算(USD)。実際の費用がこれを超えたら通知する"
  type        = number
  default     = 33
}

variable "forecast_alert_percent" {
  description = "予測の費用が予算の何%を超えたら通知するか"
  type        = number
  default     = 60
}

variable "anomaly_threshold_usd" {
  description = "コスト異常検出で、影響額がいくら以上なら通知するか(USD)"
  type        = number
  default     = 5
}

variable "anomaly_monitor_name" {
  description = "サービス別のコスト異常モニターの名前。AWS が自動で作ったものを取り込む場合は、その名前に合わせる"
  type        = string
  default     = "Default-Services-Monitor"
}
