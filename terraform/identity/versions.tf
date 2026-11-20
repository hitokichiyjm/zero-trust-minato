terraform {
  # use_lockfile(S3 のネイティブのロック)を使うため 1.11 以上
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}
