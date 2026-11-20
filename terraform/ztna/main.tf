# ZTNA:VPN なしで社内アプリにつなぐ(DOC-03 6章)
#   利用者のブラウザ → Cloudflare Access(本人確認・ポリシー)→ Tunnel → cloudflared(VPC の中)→ アプリ(127.0.0.1)
#
# P2-2a:まずはメールのワンタイム PIN で、管理者だけが入れる形で、全体がつながることを確かめる
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

# P2-2a:管理者のメールアドレスだけを許す(ワンタイム PIN でサインイン)
resource "cloudflare_zero_trust_access_policy" "admins" {
  account_id = var.cloudflare_account_id
  name       = "${var.project}-admins"
  decision   = "allow"

  include = [for e in var.admin_emails : { email = { email = e } }]
}

resource "cloudflare_zero_trust_access_application" "app" {
  for_each = local.all_apps

  account_id       = var.cloudflare_account_id
  name             = "${var.project}-${each.key}"
  domain           = each.value.hostname
  type             = "self_hosted"
  session_duration = each.value.session

  policies = [{
    id         = cloudflare_zero_trust_access_policy.admins.id
    precedence = 1
  }]
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
