# 3観点のダッシュボード(FR-DB-01)と、月ごとの推移(FR-DB-04)
#   上の段:直近6時間の最大(Maximum、6時間)。下の段:直近30日の推移(1日ごとの最大)

locals {
  metric_titles = {
    SecurityScore            = "① Security Hub のスコア(%)"
    ConfigNonCompliant       = "② Config の非準拠(規則ごとの合計)"
    LongTermAccessKeys       = "③ 長期のアクセスキー(目標0)"
    GuardDutyOpenHighFinding = "④ 未対応の GuardDuty(High 以上)"
    CloudflareAccessDenied   = "⑤ Cloudflare Access で拒否(24時間)"
    SignInFailures           = "⑥ サインインの失敗(24時間)"
    OpenAlerts               = "⑦ 未対応のアラート(Medium 以上)"
    OverdueAlerts            = "⑧ 期限切れのアラート(目標0)"
    AutoRemediations         = "⑨ 自動対応(24時間)"
    MeanTimeToResolveHours   = "⑩ 対応までの平均時間(時間、30日)"
  }

  dashboards = {
    risk     = { title = "リスク:弱いところはどこか", metrics = ["SecurityScore", "ConfigNonCompliant", "LongTermAccessKeys"] }
    threat   = { title = "脅威:今、何が起きているか", metrics = ["GuardDutyOpenHighFinding", "CloudflareAccessDenied", "SignInFailures"] }
    response = { title = "対応状況:ちゃんと対応できているか", metrics = ["OpenAlerts", "OverdueAlerts", "AutoRemediations", "MeanTimeToResolveHours"] }
  }
}

resource "aws_cloudwatch_dashboard" "this" {
  for_each = local.dashboards

  provider       = aws.security
  dashboard_name = "${var.project}-${each.key}"

  dashboard_body = jsonencode({
    widgets = concat(
      [{
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 2
        properties = {
          markdown = "## ${each.value.title}\n指標の取り方は DOC-03 10章。月次の振り返りは DOC-04 OP-50"
        }
      }],
      [for i, m in each.value.metrics : {
        type   = "metric"
        x      = (i % 4) * 6
        y      = 2
        width  = 6
        height = 4
        properties = {
          title   = "${local.metric_titles[m]}:直近6時間の最大"
          view    = "singleValue"
          region  = var.aws_region
          stat    = "Maximum"
          period  = 21600
          metrics = [[local.namespace, m]]
        }
      }],
      [for i, m in each.value.metrics : {
        type   = "metric"
        x      = (i % 2) * 12
        y      = 6 + floor(i / 2) * 6
        width  = 12
        height = 6
        properties = {
          title   = "${local.metric_titles[m]}:30日の推移"
          view    = "timeSeries"
          region  = var.aws_region
          stat    = "Maximum"
          period  = 86400
          start   = "-P30D"
          metrics = [[local.namespace, m]]
        }
      }],
    )
  })
}
