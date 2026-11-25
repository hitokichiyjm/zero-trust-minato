# ZTNA:VPN なしで社内アプリにつなぐ(DOC-03 6章)
#   利用者のブラウザ → Cloudflare Access(本人確認・ポリシー)→ Tunnel → cloudflared(VPC の中)→ アプリ(127.0.0.1)
#
# P2-2a:まずはメールのワンタイム PIN で、管理者だけが入れる形で、全体がつながることを確かめた
# P2-2b:Identity Center を SAML の IdP にし、グループごとのポリシーに切り替える

locals {
  # 環境ごとのアプリ(DOC-03 6.2)
  envs = {
    prod = {
      vpc_cidr = "10.10.0.0/16"
      apps = {
        crm        = { port = 8081, title = "顧客管理(デモ)", session = "8h" }
        accounting = { port = 8082, title = "経理(デモ)", session = "8h" }
        wiki       = { port = 8083, title = "社内 Wiki(デモ)", session = "24h" }
      }
    }
    dev = {
      vpc_cidr = "10.20.0.0/16"
      apps = {
        dev = { port = 8081, title = "検証アプリ(デモ)", session = "8h" }
      }
    }
  }

  # すべてのアプリを1つの一覧に(ホスト名 → 環境とアプリ)
  all_apps = merge([
    for env, e in local.envs : {
      for name, app in e.apps : name => merge(app, { env = env, hostname = "${name}.${var.domain}" })
    }
  ]...)
}

# =====================================================================
# 1. Cloudflare Tunnel(環境ごとに1つ)
# =====================================================================

# トンネルの秘密(32バイト)は Terraform が作る。
# Cloudflare から「トークンを取得」すると編集の権限が必要になり、CI(読み取り専用)の plan ができない。
# 秘密を自分で持てば、トークン(アカウントID・トンネルID・秘密の組)を自分で組み立てられる。
resource "random_bytes" "tunnel_secret" {
  for_each = local.envs
  length   = 32
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "this" {
  for_each = local.envs

  account_id    = var.cloudflare_account_id
  name          = "${var.project}-${each.key}"
  config_src    = "cloudflare" # 転送の設定は Cloudflare 側(このコード)で持つ
  tunnel_secret = random_bytes.tunnel_secret[each.key].base64
}

locals {
  # cloudflared のトークンの形式:{"a": アカウントID, "t": トンネルID, "s": 秘密} を Base64 にしたもの
  tunnel_tokens = {
    for env, t in cloudflare_zero_trust_tunnel_cloudflared.this : env => base64encode(jsonencode({
      a = var.cloudflare_account_id
      t = t.id
      s = random_bytes.tunnel_secret[env].base64
    }))
  }
}

# ホスト名ごとに、サーバーの中のどのポートへ渡すか
resource "cloudflare_zero_trust_tunnel_cloudflared_config" "this" {
  for_each = local.envs

  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.this[each.key].id

  config = {
    ingress = concat(
      [for name, app in each.value.apps : {
        hostname = "${name}.${var.domain}"
        service  = "http://localhost:${app.port}"
      }],
      # どれにも当たらない通信は 404 にする
      [{ service = "http_status:404" }],
    )
  }
}

# =====================================================================
# 2. DNS(アプリのホスト名 → トンネル)
# =====================================================================

data "cloudflare_zone" "this" {
  filter = {
    name = var.domain
  }
}

resource "cloudflare_dns_record" "app" {
  for_each = local.all_apps

  zone_id = data.cloudflare_zone.this.zone_id
  name    = each.value.hostname
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.this[each.value.env].id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
  comment = "Managed by Terraform (${var.project})"
}

# =====================================================================
# 3. Cloudflare Access(アプリごとに、アクセスのたびに本人を確かめる)
# =====================================================================

# P2-2b:Identity Center を SAML の IdP にし、グループごとに許可する(DOC-03 6.3)
#   Identity Center は SAML の属性 groups に、所属するグループの ID を入れて渡す(属性マッピング ${user:groups})。
#   そこで、グループの名前から ID を引いて、ポリシーの条件にする。

# Identity Center のアプリ(SAML 2.0)は API で作れないため、画面で作る(docs/build/P2_完成形.md の P2-2b)。
# ここでは、そのアプリのメタデータの値を変数で受け取る(どれも公開しない)。
resource "cloudflare_zero_trust_access_identity_provider" "identity_center" {
  account_id = var.cloudflare_account_id
  name       = "AWS IAM Identity Center"
  type       = "saml"

  config = {
    issuer_url           = var.saml_issuer_url
    sso_target_url       = var.saml_sso_url
    idp_public_certs     = [var.saml_certificate]
    email_attribute_name = "email"
    attributes           = ["email", "groups"]
    sign_request         = false
  }
}

data "aws_ssoadmin_instances" "this" {}

locals {
  identity_store_id = tolist(data.aws_ssoadmin_instances.this.identity_store_ids)[0]

  # アプリごとに入れるグループ(DOC-03 6.3)
  #   wiki は「外部委託者以外の全員」。除外の条件ではなく、許すグループを並べる(新しいグループは既定で入れない)
  app_groups = {
    crm        = ["g-sales", "g-executive", "g-it-admin"]
    accounting = ["g-backoffice", "g-executive", "g-it-admin"]
    wiki       = ["g-it-admin", "g-executive", "g-developer", "g-sales", "g-backoffice"]
    dev        = ["g-developer", "g-contractor", "g-it-admin"]
  }

  all_groups = toset(flatten(values(local.app_groups)))
}

# グループは identity スタックで作ったもの。名前から ID を引く
data "aws_identitystore_group" "this" {
  for_each = local.all_groups

  identity_store_id = local.identity_store_id

  alternate_identifier {
    unique_attribute {
      attribute_path  = "DisplayName"
      attribute_value = each.key
    }
  }
}

resource "cloudflare_zero_trust_access_policy" "app" {
  for_each = local.app_groups

  account_id = var.cloudflare_account_id
  name       = "${var.project}-${each.key}"
  decision   = "allow"

  # include はどれか1つに当てはまれば許可(OR)
  include = [for g in each.value : {
    saml = {
      attribute_name       = "groups"
      attribute_value      = data.aws_identitystore_group.this[g].group_id
      identity_provider_id = cloudflare_zero_trust_access_identity_provider.identity_center.id
    }
  }]
}

resource "cloudflare_zero_trust_access_application" "app" {
  for_each = local.all_apps

  account_id       = var.cloudflare_account_id
  name             = "${var.project}-${each.key}"
  domain           = each.value.hostname
  type             = "self_hosted"
  session_duration = each.value.session

  # サインインは Identity Center だけ(ワンタイム PIN などは使わせない)
  allowed_idps              = [cloudflare_zero_trust_access_identity_provider.identity_center.id]
  auto_redirect_to_identity = true

  policies = [{
    id         = cloudflare_zero_trust_access_policy.app[each.key].id
    precedence = 1
  }]
}

# Identity Center 側でも、アプリを使えるグループを割り当てる(割り当てのない人は SAML の応答をもらえない)
resource "aws_ssoadmin_application_assignment" "cloudflare" {
  for_each = local.all_groups

  application_arn = var.sso_application_arn
  principal_id    = data.aws_identitystore_group.this[each.key].group_id
  principal_type  = "GROUP"
}

# ---- Zero Trust の組織の設定(FR-AC-07:本番アプリに戻るときの再認証) ----
# アプリのセッション(上の session)が切れたとき、Cloudflare は組織のセッション(全体のセッション)が
# 残っていれば、Identity Center に戻らずに新しいトークンを出す。Identity Center のセッションが残っていれば、
# パスキーなしで SAML の応答が返る。そこで、どちらも短くして、アプリのセッションが切れたあとは
# パスキーで確かめ直す形にする(Identity Center のセッションの長さは API がないため画面で設定する。DOC-04 OP-46)。
#
# 組織は Zero Trust を有効にしたときに作られたもの。import で Terraform の管理に入れる(apply のときに取り込まれる)。
import {
  to = cloudflare_zero_trust_organization.this
  id = var.cloudflare_account_id
}

# チームのドメインと名前などは、今の値をそのまま使う(コードに書かず、変えない)
data "cloudflare_zero_trust_organization" "current" {
  account_id = var.cloudflare_account_id
}

resource "cloudflare_zero_trust_organization" "this" {
  account_id  = var.cloudflare_account_id
  auth_domain = data.cloudflare_zero_trust_organization.current.auth_domain
  name        = data.cloudflare_zero_trust_organization.current.name

  # 組織のセッション(全体のセッション)。Identity Center のセッションと同じ長さにする
  session_duration = var.access_global_session_duration

  # 今の値のまま(書かないと、plan で null に変える差分が出る)
  deny_unmatched_requests                     = false
  deny_unmatched_requests_exempted_zone_names = []

  # 使っていないサービストークンの自動の処理(無効のまま)。
  # 組織の更新は全体を送るため、3つの項目がそろっていないと API が 400(12062)で断る。
  # 今の値は enabled=false で、action と日数は空。無効のままにし、必須の2つには害のない値を入れる:
  #   action は「削除」より戻せる「無効にする」(disable)、日数は API の最小(30日。範囲は 30〜365)
  service_token_inactivity = {
    enabled                   = false
    action                    = "disable"
    inactivity_threshold_days = 30
  }
}

# =====================================================================
# 4. 社内アプリのサーバー(AWS の prod と dev)
# =====================================================================

module "host_prod" {
  source       = "../modules/app-host"
  providers    = { aws = aws.prod }
  project      = var.project
  env          = "prod"
  vpc_cidr     = local.envs.prod.vpc_cidr
  apps         = { for k, v in local.envs.prod.apps : k => { port = v.port, title = v.title } }
  tunnel_token = local.tunnel_tokens["prod"]
}

module "host_dev" {
  source       = "../modules/app-host"
  providers    = { aws = aws.dev }
  project      = var.project
  env          = "dev"
  vpc_cidr     = local.envs.dev.vpc_cidr
  apps         = { for k, v in local.envs.dev.apps : k => { port = v.port, title = v.title } }
  tunnel_token = local.tunnel_tokens["dev"]
}

output "app_urls" {
  description = "社内アプリの URL"
  value       = { for k, a in local.all_apps : k => "https://${a.hostname}" }
}

output "instance_ids" {
  description = "サーバーのインスタンスID(起動・停止に使う)"
  value       = { prod = module.host_prod.instance_id, dev = module.host_dev.instance_id }
}
