# 最初の apply(状態ファイル用のバケットを作る)が終わったら、
# このファイルを backend.tf に名前を変えて、terraform init -migrate-state を実行する。
# バケット名は公開しないため、backend.hcl(Git に入らない)から渡す:
#   terraform init -migrate-state -backend-config=backend.hcl
terraform {
  backend "s3" {
    key          = "bootstrap/terraform.tfstate"
    region       = "ap-northeast-1"
    encrypt      = true
    use_lockfile = true
  }
}
