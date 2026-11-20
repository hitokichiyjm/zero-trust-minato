# AWS Config のレコーダー(1アカウント・1リージョンに1つ)
# 記録するリソースを絞り、変更があったときだけ記録する(DOC-03 7章、V-2)

terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

variable "log_bucket" {
  description = "設定の記録を送る S3 バケット(log-archive アカウント)"
  type        = string
}

variable "resource_types" {
  description = "記録するリソースの種類"
  type        = list(string)
}

# Config が使うサービスリンクロール(AWS が中身を管理する)
resource "aws_iam_service_linked_role" "config" {
  aws_service_name = "config.amazonaws.com"
}

resource "aws_config_configuration_recorder" "this" {
  name     = "default"
  role_arn = aws_iam_service_linked_role.config.arn

  recording_group {
    all_supported                 = false
    include_global_resource_types = false
    resource_types                = var.resource_types
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
}

resource "aws_config_delivery_channel" "this" {
  name           = "default"
  s3_bucket_name = var.log_bucket

  depends_on = [aws_config_configuration_recorder.this]
}

resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}
