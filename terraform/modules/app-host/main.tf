# 社内アプリのサーバー(1環境につき1台)
#
# ネットワークの考え方(DOC-03 6.3):
# - サブネットはプライベートだけ。IPv4 のパブリック IP は付けない(インターネットから届かない、料金もかからない)
# - 外向きの通信は IPv6 の Egress-only インターネットゲートウェイだけ(NAT Gateway の時間課金をかけない)
# - 受信のルールは1つもない。cloudflared が内側から外向きに Cloudflare へトンネルを張る
#
# 必要な通信先は IPv6 で届くことを確かめている(V-5):Cloudflare Tunnel、pkg.cloudflare.com、
# Amazon Linux のパッケージ、SSM のデュアルスタックのエンドポイント(ssm.<region>.api.aws)

terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

variable "project" {
  type = string
}

variable "env" {
  description = "環境の名前(prod、dev)"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC の IPv4 の範囲(VPC の中だけで使う。インターネットには出ない)"
  type        = string
}

variable "apps" {
  description = "このサーバーで動かすアプリ(名前 → ポートと表示名)"
  type = map(object({
    port  = number
    title = string
  }))
}

variable "tunnel_token" {
  description = "cloudflared のトンネルのトークン(SSM Parameter Store に保存し、起動時に読む)"
  type        = string
  sensitive   = true
}

variable "instance_type" {
  type    = string
  default = "t4g.nano"
}

data "aws_region" "current" {}

locals {
  name       = "${var.project}-${var.env}"
  param_name = "/${var.project}/${var.env}/tunnel-token"
}

# ---- ネットワーク ----
resource "aws_vpc" "this" {
  #checkov:skip=CKV2_AWS_11:VPC フローログは P2-3(ログ集約)で、費用を見て検討する
  cidr_block                       = var.vpc_cidr
  assign_generated_ipv6_cidr_block = true
  enable_dns_support               = true
  enable_dns_hostnames             = true

  tags = { Name = local.name }
}

# 既定のセキュリティグループは、すべての通信を拒否する(CIS の推奨)
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
}

resource "aws_subnet" "private" {
  vpc_id                          = aws_vpc.this.id
  cidr_block                      = cidrsubnet(var.vpc_cidr, 8, 1)
  ipv6_cidr_block                 = cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, 1)
  assign_ipv6_address_on_creation = true
  map_public_ip_on_launch         = false
  availability_zone               = "${data.aws_region.current.region}a"

  tags = { Name = "${local.name}-private" }
}

resource "aws_egress_only_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = local.name }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id

  # IPv6 は外向きだけ(Egress-only)。IPv4 のインターネットへの経路はない
  route {
    ipv6_cidr_block        = "::/0"
    egress_only_gateway_id = aws_egress_only_internet_gateway.this.id
  }

  tags = { Name = "${local.name}-private" }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# 受信は1つもない。送信は HTTPS(パッケージ・AWS の API)と、Cloudflare Tunnel(7844)だけ
resource "aws_security_group" "app" {
  name        = "${local.name}-app"
  description = "App host: no inbound. Outbound only HTTPS and Cloudflare Tunnel over IPv6"
  vpc_id      = aws_vpc.this.id

  egress {
    description      = "HTTPS (packages, AWS APIs, Cloudflare)"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    description      = "Cloudflare Tunnel (TCP)"
    from_port        = 7844
    to_port          = 7844
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    description      = "Cloudflare Tunnel (QUIC)"
    from_port        = 7844
    to_port          = 7844
    protocol         = "udp"
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = { Name = "${local.name}-app" }
}

# ---- トンネルのトークン(SSM Parameter Store) ----
resource "aws_ssm_parameter" "tunnel_token" {
  #checkov:skip=CKV_AWS_337:SecureString で AWS 管理のキー(aws/ssm)で暗号化している。顧客管理のキーは月 1 USD かかるため使わない
  name        = local.param_name
  description = "cloudflared tunnel token for ${var.env}"
  type        = "SecureString"
  value       = var.tunnel_token
}

# ---- サーバーのロール ----
data "aws_iam_policy_document" "ec2_trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "read_token" {
  statement {
    sid       = "ReadTunnelToken"
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.tunnel_token.arn]
  }
}

resource "aws_iam_role" "app" {
  name               = "${local.name}-app-host"
  description        = "App host: read its tunnel token and use Session Manager"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json
}

resource "aws_iam_role_policy" "read_token" {
  name   = "read-tunnel-token"
  role   = aws_iam_role.app.id
  policy = data.aws_iam_policy_document.read_token.json
}

# Session Manager(SSH の代わり)。SSM のデュアルスタックのエンドポイントで使えるかは、構築後に確かめる
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "app" {
  name = "${local.name}-app-host"
  role = aws_iam_role.app.name
}

# ---- サーバー ----
data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

resource "aws_instance" "app" {
  #checkov:skip=CKV_AWS_126:詳細モニタリングは使わない(費用のため。基本のモニタリングで足りる)
  #checkov:skip=CKV_AWS_135:t4g は EBS 最適化が既定で有効
  ami                         = data.aws_ssm_parameter.al2023_arm64.insecure_value
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.private.id
  vpc_security_group_ids      = [aws_security_group.app.id]
  iam_instance_profile        = aws_iam_instance_profile.app.name
  associate_public_ip_address = false
  ipv6_address_count          = 1

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    http_endpoint               = "enabled"
  }

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 8
  }

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    region     = data.aws_region.current.region
    param_name = local.param_name
    apps       = var.apps
  })

  tags = { Name = "${local.name}-app" }

  depends_on = [aws_ssm_parameter.tunnel_token, aws_iam_role_policy.read_token]

  lifecycle {
    # AMI の更新で勝手に作り直さない(作り直すときは手で指定する)
    ignore_changes = [ami]
  }
}

output "instance_id" {
  value = aws_instance.app.id
}

output "vpc_id" {
  value = aws_vpc.this.id
}
