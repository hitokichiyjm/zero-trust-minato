# zero-trust-minato

架空の小さな会社「ミナト企画」(社員10名、社内アプリあり、リモートワークあり)を、ゼロトラストの考え方で作り直すプロジェクトです。
要件定義から設計・構築・運用までを、1人で行っています。インフラはすべて Terraform でコード化しています。

## 設計書
| 文書 | 内容 |
|---|---|
| [DOC-01 要件定義書](docs/01_要件定義書.md) | 会社の想定、課題、機能要件・非機能要件、フェーズ分け |
| [DOC-02 脅威分析書](docs/02_脅威分析書.md) | 資産、信頼境界、STRIDE による脅威の洗い出し、攻撃シナリオ |
| [DOC-03 方式設計書](docs/03_方式設計書.md) | 方式の選定理由、構成図、各領域の設計、概算費用 |
| [DOC-04 運用手順書](docs/04_運用手順書.md) | 定常運用、アラート対応、インシデント対応、環境の削除 |

## 構成(予定)
| 領域 | 使うもの |
|---|---|
| ID 基盤 | AWS IAM Identity Center(SSO + FIDO2 の MFA) |
| アクセス制御 | Cloudflare Zero Trust(Access + Tunnel)で VPN なしの接続 |
| 検知 | AWS Organizations(5アカウント)、GuardDuty、Security Hub、Config、CloudTrail |
| 自動対応 | EventBridge + Lambda |
| ログ | S3(オブジェクトロック)+ Athena |
| ダッシュボード | CloudWatch(リスク・脅威・対応状況の3枚) |

## 進み具合
| フェーズ | 内容 | 状態 |
|---|---|---|
| P0 準備 | 費用アラート、秘密情報の検査、Terraform の土台(状態ファイル、GitHub OIDC) | 完了([作業記録](ops-log/2026-11_P0.md)) |
| P1 最小構成 | マルチアカウント、SSO + MFA、検知、通知と自動対応 | 未着手 |
| P2 完成形 | ZTNA、ログ集約、ダッシュボードとエスカレーション | 未着手 |
| P3 追加 | RISKEN、ハイブリッド接続 | 未着手 |

## ディレクトリ
```
docs/                 設計書
docs/build/           フェーズごとの構築手順
terraform/bootstrap/  状態ファイル用 S3、GitHub OIDC、費用アラート
.github/workflows/    terraform plan と Checkov(plan のみ。apply は手元から)
ops-log/              作業記録(つまずいたことと対応を含む)
```

## 秘密情報の扱い
- `*.tfvars`、`backend.hcl`、状態ファイルはリポジトリに入れません(`.gitignore`)
- コミットの前に gitleaks で検査します(`.pre-commit-config.yaml`)
- GitHub Actions から AWS へは OIDC で接続し、アクセスキーは使いません
