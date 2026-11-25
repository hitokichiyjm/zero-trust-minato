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

# ---- Identity Center の SAML アプリ(画面で作ったもの)の値。どれも公開しない ----
variable "sso_application_arn" {
  description = "Identity Center のアプリ(Cloudflare Access 用の SAML 2.0)の ARN"
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^arn:aws:sso::[0-9]{12}:application/ssoins-[0-9a-zA-Z]+/apl-[0-9a-zA-Z]+$", var.sso_application_arn))
    error_message = "Identity Center のアプリの ARN(arn:aws:sso::<12桁>:application/ssoins-.../apl-...)の形で指定してください。"
  }
}

variable "saml_sso_url" {
  description = "メタデータの SingleSignOnService の Location(IAM Identity Center のサインイン URL)"
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^https://[A-Za-z0-9.-]+/[^[:space:]]+$", var.saml_sso_url))
    error_message = "https:// で始まり、パスを含む URL で指定してください(空白は入れない)。"
  }
}

variable "saml_issuer_url" {
  description = "メタデータの entityID(IAM Identity Center の発行者 URL)"
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^https://[A-Za-z0-9.-]+/[^[:space:]]+$", var.saml_issuer_url))
    error_message = "https:// で始まり、パスを含む URL で指定してください(空白は入れない)。"
  }
}

variable "saml_certificate" {
  description = "メタデータの X509Certificate(署名の検証に使う公開鍵の証明書。BEGIN/END の行なしの Base64)"
  type        = string
  sensitive   = true

  validation {
    condition = (
      length(trimspace(var.saml_certificate)) > 0
      && !strcontains(var.saml_certificate, "-----")
      && can(regex("^[A-Za-z0-9+/=[:space:]]+$", var.saml_certificate))
    )
    error_message = "証明書は空にせず、BEGIN/END の行を除いた Base64 だけで指定してください。"
  }
}

variable "access_global_session_duration" {
  description = "Cloudflare Zero Trust の組織のセッション(全体のセッション)の長さ。Identity Center のセッションと同じにする(DOC-03 6.2、FR-AC-07)"
  type        = string
  default     = "1h"

  validation {
    condition     = can(regex("^[0-9]+(m|h)$", var.access_global_session_duration))
    error_message = "「30m」や「1h」の形で指定してください。"
  }
}
