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
| P1 最小構成 | マルチアカウント、SSO + MFA、検知、通知と自動対応 | 完了([作業記録と受け入れ基準の確認](ops-log/2026-11_P1.md)) |
| P2 完成形 | ZTNA、ログ集約、ダッシュボードとエスカレーション | 未着手 |
| P3 追加 | RISKEN、ハイブリッド接続 | 未着手 |

## できていること(P1 まで)
| 項目 | 内容 |
|---|---|
| アカウント | AWS Organizations で5つ(管理、security、log-archive、prod、dev)。SCP で、東京以外のリージョン・IAM ユーザーの作成・検知とログの停止を禁止 |
| ID | IAM Identity Center(MFA は FIDO2 のみ)。役割ごとに6グループ・4許可セット。**IAM ユーザーは0** |
| 検知 | GuardDuty・Security Hub CSPM(FSBP)・Config・IAM Access Analyzer を全アカウントで有効化し、security に集約 |
| 自動対応 | 危険なポートの全開放を **12秒で自動的に閉じる**。検知を止める操作の試み、重大度 HIGH 以上の検知を通知 |
| ログ | 組織の CloudTrail を、オブジェクトロック(1年)の S3 に保管 |
| 開発の流れ | 変更は PR だけ。7つのスタックの plan と Checkov が通らないとマージできない。公開ログでアカウントIDなどを隠す |

## ディレクトリ
```
docs/                 設計書(要件定義、脅威分析、方式設計、運用手順)
docs/build/           フェーズごとの構築手順
terraform/bootstrap/  状態ファイル用 S3、GitHub OIDC、費用アラート
terraform/org/        Organizations、OU、アカウント、SCP
terraform/identity/   IAM Identity Center のグループ、許可セット、割り当て
terraform/baseline/   全アカウントの予防的な基本設定、CI 用の読み取り専用ロール
terraform/logging/    組織の CloudTrail、ログ用 S3
terraform/detection/  GuardDuty、Security Hub CSPM、Config、Access Analyzer
terraform/response/   イベントの集約、通知と自動修復
terraform/modules/    共通のモジュール
lambda/response/      通知と自動修復の Lambda(Python)
scripts/              取り込み(import)などの補助スクリプト
.github/workflows/    terraform plan と Checkov(plan のみ。apply は手元から)
ops-log/              作業記録(つまずいたこと・インシデントと対応、受け入れ基準の確認)
```

## 秘密情報の扱い
- `*.tfvars`、`backend.hcl`、状態ファイルはリポジトリに入れません(`.gitignore`)
- コミットの前に gitleaks で検査します(`.pre-commit-config.yaml`)
- GitHub Actions から AWS へは OIDC で接続し、アクセスキーは使いません
