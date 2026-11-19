# GitHub Actions から、アクセスキーなしで AWS に入るための設定(NFR-SEC-02, NFR-SEC-06)
# このロールは terraform plan 専用で、読み取りしかできない(apply は手元から SSO で行う。DOC-03 12.2)

# GitHub の OIDC トークンの sub は、既定で「変わらないID」を含む形式(immutable subject)になっている。
#   repo:<owner>@<ownerのID>/<repo>@<repoのID>:<きっかけ>
# 名前だけで判定すると、リポジトリを消した後に同じ名前で作り直された場合に、別人がこのロールを使えてしまう。
# ID を含めることで、それを防ぐ。
locals {
  github_owner      = split("/", var.github_repository)[0]
  github_repo       = split("/", var.github_repository)[1]
  github_sub_prefix = "repo:${local.github_owner}@${var.github_owner_id}/${local.github_repo}@${var.github_repository_id}"
}

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "github_plan_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # 自分のリポジトリの「プルリクエスト」と「main ブランチ」からだけ使える(TH-29)
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "${local.github_sub_prefix}:pull_request",
        "${local.github_sub_prefix}:ref:refs/heads/main",
      ]
    }
  }
}

resource "aws_iam_role" "github_plan" {
  name = "${var.project}-github-plan"
  # IAM の description は ASCII などの限られた文字しか使えない(日本語は不可)
  description          = "Read-only role for terraform plan from GitHub Actions"
  assume_role_policy   = data.aws_iam_policy_document.github_plan_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "github_plan_readonly" {
  role       = aws_iam_role.github_plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# plan のときに、状態ファイルのロック(.tflock)を作って消すことだけを追加で許す
data "aws_iam_policy_document" "github_plan_lock" {
  statement {
    sid       = "StateLockFile"
    actions   = ["s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.tfstate.arn}/*.tflock"]
  }
}

resource "aws_iam_role_policy" "github_plan_lock" {
  name   = "terraform-state-lock"
  role   = aws_iam_role.github_plan.id
  policy = data.aws_iam_policy_document.github_plan_lock.json
}
