"""エスカレーションの Lambda(FR-DB-03、UC-7、K-5、DOC-03 8.4。P2-4)

- 1時間ごとに、Security Hub の検知のうち、ワークフローの状態が NEW・NOTIFIED のままで、
  対応期限(DOC-01 NFR-OPS-02)を過ぎたものを探す
    CRITICAL:4時間 → 代表(エスカレーション用の SNS)
    HIGH    :24時間 → 代表
    MEDIUM  :3営業日 → 情報システム担当に再通知(いつもの通知の SNS)
- 送った検知には UserDefinedFields の escalatedAt を書き、2回送らない
- 期限を過ぎて対応されていない件数を、ダッシュボードの⑧(OverdueAlerts)として出す
- 1回の実行で、送り先ごとに1通にまとめる(件数が多くてもメールが溢れないように)
- ESCALATION_START(日本時間の日付)より前に見つかった検知は送らず、⑧ にも数えない
  (始めた時点でたまっていた検知は、受け入れたリスクを含むため。P2-5 で SUPPRESSED などに整理する)
- UserDefinedFields の assignee がある検知は、初動済み(担当者が決まっている)として送らず、⑧ にも数えない
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone

import boto3

import notify_lib

logger = logging.getLogger()
logger.setLevel(logging.INFO)

JST = timezone(timedelta(hours=9))
NAMESPACE = os.environ.get("METRIC_NAMESPACE", "ZeroTrustMinato")
MAX_LINES = 20

_securityhub = boto3.client("securityhub")
_sns = boto3.client("sns")
_cw = boto3.client("cloudwatch")


def add_business_days(start, days):
    """土日を除いて days 営業日を足す(日本時間で数える。祝日は考えない)。"""
    t = start.astimezone(JST)
    added = 0
    while added < days:
        t += timedelta(days=1)
        if t.weekday() < 5:
            added += 1
    return t


def due_time(severity, start):
    if severity == "CRITICAL":
        return start + timedelta(hours=4), "ceo"
    if severity == "HIGH":
        return start + timedelta(hours=24), "ceo"
    if severity == "MEDIUM":
        return add_business_days(start, 3), "it"
    return None, None


def _parse(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def start_cutoff():
    """エスカレーションを始めた日の 0 時(日本時間)。これより前に見つかった検知は対象外"""
    day = os.environ.get("ESCALATION_START", "")
    if not day:
        return None
    return datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=JST)


def _findings():
    filters = {
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}, {"Value": "NOTIFIED", "Comparison": "EQUALS"}],
        "SeverityLabel": [{"Value": v, "Comparison": "EQUALS"} for v in ("CRITICAL", "HIGH", "MEDIUM")],
    }
    token = None
    while True:
        kw = {"Filters": filters, "MaxResults": 100}
        if token:
            kw["NextToken"] = token
        res = _securityhub.get_findings(**kw)
        yield from res.get("Findings", [])
        token = res.get("NextToken")
        if not token:
            return


def classify(findings, now, cutoff=None):
    """期限切れの件数と、送るべき検知(送り先ごと)を返す。"""
    overdue = 0
    to_send = {"ceo": [], "it": []}
    for f in findings:
        if (f.get("Compliance") or {}).get("Status") == "PASSED":
            continue
        fields = f.get("UserDefinedFields") or {}
        if fields.get("assignee"):
            continue  # 担当者が決まっている(初動済み)
        sev = (f.get("Severity") or {}).get("Label", "")
        start_ts = f.get("FirstObservedAt") or f.get("CreatedAt")
        if not start_ts:
            continue
        start = _parse(start_ts)
        if cutoff is not None and start < cutoff:
            continue  # エスカレーションを始める前からあった検知
        due, target = due_time(sev, start)
        if due is None or now < due:
            continue
        overdue += 1
        if fields.get("escalatedAt"):
            continue
        to_send[target].append(f)
    return overdue, to_send


def _lines(findings, now):
    lines = []
    for f in findings[:MAX_LINES]:
        sev = f.get("Severity", {}).get("Label", "")
        start = _parse(f.get("FirstObservedAt") or f.get("CreatedAt"))
        hours = int((now - start).total_seconds() // 3600)
        lines.append(f"- [{sev}] {f.get('Title', '')}(アカウント {f.get('AwsAccountId')}、{hours} 時間前から未対応)")
    if len(findings) > MAX_LINES:
        lines.append(f"- ほか {len(findings) - MAX_LINES} 件(Security Hub で確かめる)")
    return lines


def _mark(findings, now):
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    for i in range(0, len(findings), 100):
        chunk = findings[i:i + 100]
        res = _securityhub.batch_update_findings(
            FindingIdentifiers=[{"Id": f["Id"], "ProductArn": f["ProductArn"]} for f in chunk],
            UserDefinedFields={"escalatedAt": stamp},
        )
        failed = res.get("UnprocessedFindings", [])
        if failed:
            logger.warning("escalatedAt を書けなかった検知:%s 件", len(failed))


def handler(event, context):
    now = datetime.now(timezone.utc)
    overdue, to_send = classify(_findings(), now, start_cutoff())

    if to_send["ceo"]:
        body = "\n".join([
            "対応期限(CRITICAL は4時間、HIGH は24時間)を過ぎても対応されていないアラートがあります。",
            "情報システム担当に状況を確かめてください(運用手順書 OP-20)。",
            "",
            *_lines(to_send["ceo"], now),
        ])
        _sns.publish(
            TopicArn=os.environ["ESCALATION_TOPIC_ARN"],
            Subject=f"[エスカレーション] 期限切れのアラート {len(to_send['ceo'])} 件"[:100],
            Message=body,
        )
        # 情報システム担当にも、代表に送ったことを知らせる
        notify_lib.send(f"代表にエスカレーションしました({len(to_send['ceo'])} 件)", _lines(to_send["ceo"], now), "HIGH")
    if to_send["it"]:
        notify_lib.send(
            f"再通知:3営業日を過ぎた MEDIUM のアラート {len(to_send['it'])} 件",
            ["対応するか、問題なければ SUPPRESSED にする(運用手順書 OP-20)", *_lines(to_send["it"], now)],
            "MEDIUM",
        )
    _mark(to_send["ceo"] + to_send["it"], now)

    _cw.put_metric_data(Namespace=NAMESPACE, MetricData=[{"MetricName": "OverdueAlerts", "Value": overdue, "Unit": "Count"}])
    result = {"overdue": overdue, "escalated_to_ceo": len(to_send["ceo"]), "renotified": len(to_send["it"])}
    logger.info(json.dumps(result))
    return result
