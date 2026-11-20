# メンバーアカウントのルートユーザーを、組織から一元管理する(P2-1、P1 の確認で見つかった F-1)
#
# - RootCredentialsManagement:メンバーのルートユーザーの認証情報(パスワード・アクセスキー・MFA)を
#   管理アカウントから消したり確かめたりできる。メンバーのルートでパスワードの再設定もできなくなる
# - RootSessions:ルートでしかできない作業(誤って閉じた S3 のバケットポリシーの削除など)が必要なときだけ、
#   管理アカウントから短時間のルートのセッションを使う
#
# Organizations で作ったアカウントのルートには、もともとパスワードがない。この設定で「後から作られる」ことも防ぐ。
resource "aws_iam_organizations_features" "this" {
  enabled_features = [
    "RootCredentialsManagement",
    "RootSessions",
  ]

  depends_on = [aws_organizations_organization.this]
}
