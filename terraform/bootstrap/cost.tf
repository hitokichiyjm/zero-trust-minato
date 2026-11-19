# 費用アラート(NFR-COST-02)
# P1 で Organizations を使い始めると、管理アカウントの予算は組織全体の費用を対象にする

resource "aws_budgets_budget" "monthly_total" {
  name         = "${var.project}-monthly-total"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # 予測が予算の60%(約3,000円)を超えそうなとき
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = var.forecast_alert_percent
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.notification_email]
  }

  # 実際の費用が予算(約5,000円)を超えたとき
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.notification_email]
  }
}

# コスト異常検出:いつもと違う費用の増え方を、サービスごとに見つける
resource "aws_ce_anomaly_monitor" "services" {
  provider = aws.us_east_1
  count    = var.create_anomaly_monitor ? 1 : 0

  name              = "${var.project}-services"
  monitor_type      = "DIMENSIONAL"
  monitor_dimension = "SERVICE"
}

locals {
  anomaly_monitor_arn = var.create_anomaly_monitor ? aws_ce_anomaly_monitor.services[0].arn : var.existing_anomaly_monitor_arn
}

resource "aws_ce_anomaly_subscription" "daily_email" {
  provider = aws.us_east_1

  name             = "${var.project}-daily-email"
  frequency        = "DAILY"
  monitor_arn_list = [local.anomaly_monitor_arn]

  subscriber {
    type    = "EMAIL"
    address = var.notification_email
  }

  threshold_expression {
    dimension {
      key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
      match_options = ["GREATER_THAN_OR_EQUAL"]
      values        = [tostring(var.anomaly_threshold_usd)]
    }
  }

  lifecycle {
    precondition {
      condition     = local.anomaly_monitor_arn != ""
      error_message = "create_anomaly_monitor = false のときは existing_anomaly_monitor_arn を指定してください。"
    }
  }
}
