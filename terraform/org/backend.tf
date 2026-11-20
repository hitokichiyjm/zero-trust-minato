# 状態ファイルは bootstrap と同じ S3 バケットに置く。バケット名は backend.hcl(Git に入らない)から渡す:
#   terraform init -backend-config=backend.hcl
terraform {
  backend "s3" {
    key          = "org/terraform.tfstate"
    region       = "ap-northeast-1"
    encrypt      = true
    use_lockfile = true
  }
}
