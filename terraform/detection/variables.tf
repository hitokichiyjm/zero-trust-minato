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

variable "tfstate_bucket" {
  description = "状態ファイルのバケット名(logging スタックの出力から、ログ用 S3 の名前を読むため)"
  type        = string
}

variable "config_resource_types" {
  description = "Config で記録するリソースの種類(費用を抑えるため、検知と自動対応に必要なものに絞る)"
  type        = list(string)
  default = [
    "AWS::EC2::Instance",
    "AWS::EC2::SecurityGroup",
    "AWS::IAM::Policy",
    "AWS::IAM::Role",
    "AWS::IAM::User",
    "AWS::S3::Bucket",
  ]
}

variable "guardduty_optional_features" {
  description = "GuardDuty の追加の保護プラン。費用を抑えるため、最初はすべて止めておく(DOC-03 7章)"
  type        = list(string)
  default = [
    "S3_DATA_EVENTS",
    "EKS_AUDIT_LOGS",
    "EBS_MALWARE_PROTECTION",
    "RDS_LOGIN_EVENTS",
    "LAMBDA_NETWORK_LOGS",
    "RUNTIME_MONITORING",
  ]
}
