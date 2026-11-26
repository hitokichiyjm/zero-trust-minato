"""ダッシュボードの指標を集める Lambda(DOC-03 10章、FR-DB-01・04。P2-4)

event = {"group": "hourly"}(1時間ごと)または {"group": "athena"}(6時間ごと)
  hourly:① SecurityScore ② ConfigNonCompliant ③ LongTermAccessKeys ④ GuardDutyOpenHighFinding
          ⑦ OpenAlerts ⑩ MeanTimeToResolveHours
  athena:⑤ CloudflareAccessDenied ⑥ SignInFailures ⑨ AutoRemediations(log-archive の Athena)
⑧ OverdueAlerts はエスカレーションの Lambda(response)が出す。

- Security Hub を止めたら USE_SECURITY_HUB=false にし、①⑦⑩ を出さない(D-1)
- 1つの指標が失敗しても、ほかの指標は出す。最後に、失敗があれば例外にする(Errors のアラームで分かる)
- ログには件数と指標の名前だけを出す
"""

import csv
import io
import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

NAMESPACE = os.environ.get("NAMESPACE", "ZeroTrustMinato")

_sh = boto3.client("securityhub")
_config = boto3.client("config")
_gd = boto3.client("guardduty")
_sts = boto3.client("sts")
_cw = boto3.client("cloudwatch")


# ---------------------------------------------------------------- Security Hub
def _findings(filters):
    token = None
    while True:
        kw = {"Filters": filters, "MaxResults": 100}
        if token:
            kw["NextToken"] = token
        res = _sh.get_findings(**kw)
        yield from res.get("Findings", [])
        token = res.get("NextToken")
        if not token:
            return


def security_score(findings):
    """① 制御ごとに、どれか1つでも FAILED なら不合格、全部 PASSED なら合格。合格の割合(%)"""
    status = {}
    for f in findings:
        cid = (f.get("Compliance") or {}).get("SecurityControlId")
        st = (f.get("Compliance") or {}).get("Status")
        if not cid or st not in ("PASSED", "FAILED"):
            continue
        if status.get(cid) == "FAILED":
            continue
        status[cid] = st
    total = len(status)
    if total == 0:
        return None
    return round(100.0 * sum(1 for s in status.values() if s == "PASSED") / total, 1)


def open_alerts(findings):
    """⑦ NEW・NOTIFIED のままの Medium 以上(PASSED の制御の結果は除く)"""
    return sum(1 for f in findings if (f.get("Compliance") or {}).get("Status") != "PASSED")


def mean_time_to_resolve_hours(findings):
    """⑩ 直近30日に RESOLVED になった検知の、最初に見つかってから対応を終えるまでの平均(時間)。
    ワークフローの状態が変わった時刻は残らない。また BatchUpdateFindings(人が RESOLVED にする操作)は
    UpdatedAt を変えない(公式の API リファレンス)。そこで、RESOLVED にするときに書くメモの時刻(Note.UpdatedAt)を使い、
    メモがなければ UpdatedAt で近似する。自動で解決した PASSED は除く。"""
    hours = []
    for f in findings:
        if (f.get("Compliance") or {}).get("Status") == "PASSED":
            continue
        start = f.get("FirstObservedAt") or f.get("CreatedAt")
        end = (f.get("Note") or {}).get("UpdatedAt") or f.get("UpdatedAt")
        if start and end:
            d = _ts(end) - _ts(start)
            hours.append(max(d.total_seconds(), 0) / 3600)
    if not hours:
        return None
    return round(sum(hours) / len(hours), 1)


def _ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


# ---------------------------------------------------------------- Config / GuardDuty / IAM
def config_noncompliant():
    """② 組織のアグリゲーターで、非準拠の規則ごとの非準拠リソース数の合計(上限付きの数)
    アグリゲーターの名前は環境変数で受け取る(DescribeConfigurationAggregators はリソースを指定できず、
    Resource "*" の権限が要るため、呼ばない)"""
    name = os.environ["AGGREGATOR_NAME"]
    total, token = 0, None
    while True:
        kw = {"ConfigurationAggregatorName": name, "Filters": {"ComplianceType": "NON_COMPLIANT"}}
        if token:
            kw["NextToken"] = token
        res = _config.describe_aggregate_compliance_by_config_rules(**kw)
        for r in res.get("AggregateComplianceByConfigRules", []):
            total += ((r.get("Compliance") or {}).get("ComplianceContributorCount") or {}).get("CappedCount", 0)
        token = res.get("NextToken")
        if not token:
            return total


def guardduty_open_high():
    """④ 委任管理者で、アーカイブされていない重大度7以上の検知の数"""
    detectors = _gd.list_detectors().get("DetectorIds", [])
    if not detectors:
        return None
    criteria = {"Criterion": {"severity": {"GreaterThanOrEqual": 7}, "service.archived": {"Equals": ["false"]}}}
    n, token = 0, None
    while True:
        kw = {"DetectorId": detectors[0], "FindingCriteria": criteria, "MaxResults": 50}
        if token:
            kw["NextToken"] = token
        res = _gd.list_findings(**kw)
        n += len(res.get("FindingIds", []))
        token = res.get("NextToken")
        if not token:
            return n


def _assume(role_arn, name):
    c = _sts.assume_role(RoleArn=role_arn, RoleSessionName=name, DurationSeconds=900)["Credentials"]
    return boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"], aws_session_token=c["SessionToken"])


def count_active_keys(report_csv):
    """認証情報レポート(CSV)で、有効なアクセスキーの数(ルートの行も含む)"""
    n = 0
    for row in csv.DictReader(io.StringIO(report_csv)):
        n += sum(1 for k in ("access_key_1_active", "access_key_2_active") if row.get(k) == "true")
    return n


def long_term_access_keys():
    """③ 全アカウントの有効なアクセスキーの数(目標0)"""
    total = 0
    for account in json.loads(os.environ["ACCOUNT_IDS"]):
        iam = _assume(f"arn:aws:iam::{account}:role/{os.environ['READER_ROLE_NAME']}", "dashboard-metrics").client("iam")
        for _ in range(10):
            if iam.generate_credential_report().get("State") == "COMPLETE":
                break
            time.sleep(2)
        total += count_active_keys(iam.get_credential_report()["Content"].decode())
    return total


# ---------------------------------------------------------------- Athena(log-archive)
def athena_queries(db, remediation_role):
    ct = f'"{db}"."cloudtrail"'
    cf = f'"{db}"."cloudflare_access_requests"'
    ct_days = "dt >= date_format(current_date - interval '1' day, '%Y/%m/%d')"
    last24 = "from_iso8601_timestamp({col}) >= current_timestamp - interval '24' hour"
    return {
        "CloudflareAccessDenied": (
            f"SELECT count(DISTINCT ray_id) FROM {cf} "
            f"WHERE dt >= date_format(current_date - interval '1' day, '%Y-%m-%d') AND allowed = false "
            f"AND {last24.format(col='created_at')}"
        ),
        "SignInFailures": (
            f"SELECT count(*) FROM {ct} WHERE {ct_days} "
            "AND eventsource IN ('signin.amazonaws.com', 'sso.amazonaws.com') "
            "AND eventname IN ('CredentialVerification', 'CredentialChallenge', 'UserAuthentication', 'Federate') "
            "AND (errorcode IS NOT NULL OR serviceeventdetails LIKE '%Failure%') "
            f"AND {last24.format(col='eventtime')}"
        ),
        "AutoRemediations": (
            f"SELECT count(*) FROM {ct} WHERE {ct_days} "
            "AND eventsource = 'ec2.amazonaws.com' AND eventname = 'RevokeSecurityGroupIngress' AND errorcode IS NULL "
            f"AND useridentity.arn LIKE '%:assumed-role/{remediation_role}/%' "
            f"AND {last24.format(col='eventtime')}"
        ),
    }


def run_athena(athena, sql, workgroup, db, timeout=120):
    qid = athena.start_query_execution(QueryString=sql, WorkGroup=workgroup, QueryExecutionContext={"Database": db})["QueryExecutionId"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        if st["State"] == "SUCCEEDED":
            rows = athena.get_query_results(QueryExecutionId=qid)["ResultSet"]["Rows"]
            return int(rows[1]["Data"][0]["VarCharValue"])
        if st["State"] in ("FAILED", "CANCELLED"):
            raise RuntimeError(f"Athena query {st['State']}: {st.get('StateChangeReason', '')[:200]}")
        time.sleep(2)
    athena.stop_query_execution(QueryExecutionId=qid)
    raise RuntimeError("Athena query timed out")


# ---------------------------------------------------------------- main
def collect(group):
    values, errors = {}, []

    def _try(name, fn):
        try:
            v = fn()
            if v is not None:
                values[name] = v
        except Exception as e:  # 1つの失敗でほかの指標を止めない
            logger.exception("指標 %s の集計に失敗しました", name)
            errors.append(f"{name}: {type(e).__name__}")

    if group == "hourly":
        if os.environ.get("USE_SECURITY_HUB", "true") == "true":
            active = {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}
            _try("SecurityScore", lambda: security_score(_findings({
                **active,
                "ProductName": [{"Value": "Security Hub", "Comparison": "EQUALS"}],
                "WorkflowStatus": [{"Value": "SUPPRESSED", "Comparison": "NOT_EQUALS"}],
            })))
            _try("OpenAlerts", lambda: open_alerts(_findings({
                **active,
                "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}, {"Value": "NOTIFIED", "Comparison": "EQUALS"}],
                "SeverityLabel": [{"Value": v, "Comparison": "EQUALS"} for v in ("MEDIUM", "HIGH", "CRITICAL")],
            })))
            since = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            _try("MeanTimeToResolveHours", lambda: mean_time_to_resolve_hours(_findings({
                "WorkflowStatus": [{"Value": "RESOLVED", "Comparison": "EQUALS"}],
                "UpdatedAt": [{"Start": since, "End": now}],
            })))
        _try("ConfigNonCompliant", config_noncompliant)
        _try("GuardDutyOpenHighFinding", guardduty_open_high)
        _try("LongTermAccessKeys", long_term_access_keys)
    elif group == "athena":
        db, wg = os.environ["ATHENA_DATABASE"], os.environ["ATHENA_WORKGROUP"]
        athena = _assume(os.environ["ATHENA_ROLE_ARN"], "dashboard-athena").client("athena")
        for name, sql in athena_queries(db, os.environ["REMEDIATION_ROLE_NAME"]).items():
            _try(name, lambda sql=sql: run_athena(athena, sql, wg, db))
    else:
        raise ValueError(f"unknown group: {group}")
    return values, errors


def handler(event, context):
    group = (event or {}).get("group", "hourly")
    values, errors = collect(group)
    if values:
        _cw.put_metric_data(Namespace=NAMESPACE, MetricData=[{"MetricName": k, "Value": float(v), "Unit": "None"} for k, v in values.items()])
    logger.info(json.dumps({"group": group, "metrics": values, "errors": errors}, ensure_ascii=False))
    if errors:
        raise RuntimeError(f"some metrics failed: {errors}")
    return {"group": group, "published": sorted(values)}
