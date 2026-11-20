"""通知の Lambda(AR-2、AR-3)

- AR-2:ルートユーザーのサインイン、ログや検知を止める操作 → すぐに通知
- AR-3:Security Hub の重大度 HIGH 以上の検知結果(GuardDuty の検知も含む)
        → 通知し、ワークフローの状態を NOTIFIED にする(同じ検知を何度も送らないため)
"""

import logging
import time

import boto3

import notify_lib

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_securityhub = boto3.client("securityhub")


def _handle_api_call(event):
    d = event["detail"]
    who = d.get("userIdentity", {}).get("arn", "不明")
    name = d.get("eventName", "")
    title = f"重要な操作:{name}"
    severity = "CRITICAL"
    if event.get("detail-type") == "AWS Console Sign In via CloudTrail":
        title = "ルートユーザーがコンソールにサインインしました"
    lines = [
        f"アカウント:{d.get('recipientAccountId', event.get('account'))}",
        f"リージョン:{d.get('awsRegion', event.get('region'))}",
        f"操作:{name}",
        f"実行した人:{who}",
        f"送信元 IP:{d.get('sourceIPAddress', '不明')}",
        f"結果:{'失敗(' + d['errorCode'] + ')' if d.get('errorCode') else '成功'}",
        f"時刻:{d.get('eventTime', event.get('time'))}",
        "対応:運用手順書 OP-20(ルートユーザーの場合は OP-33)",
    ]
    notify_lib.send(title, lines, severity)


def _handle_findings(event):
    for f in event["detail"].get("findings", []):
        sev = f.get("Severity", {}).get("Label", "")
        resources = ", ".join(r.get("Id", "") for r in f.get("Resources", [])[:3])
        lines = [
            f"アカウント:{f.get('AwsAccountId')}",
            f"検知した仕組み:{f.get('ProductName', '')}",
            f"種類:{', '.join(f.get('Types', [])[:2])}",
            f"内容:{f.get('Title', '')}",
            f"対象:{resources}",
            f"最初に見つけた時刻:{f.get('FirstObservedAt', f.get('CreatedAt', ''))}",
            "対応:運用手順書 OP-20(初動の期限:CRITICAL は4時間、HIGH は24時間)",
        ]
        notify_lib.send(f"検知:{f.get('Title', '')}", lines, sev)

        _mark_notified(f)


def _mark_notified(finding):
    """通知したことを Security Hub に記録する(ダッシュボードの「対応状況」にも使う)。

    batch_update_findings は失敗しても例外を出さず、UnprocessedFindings に入れて返す。
    取り込み直後は検知結果がまだ見つからないことがあるため、間を空けて数回やり直す。
    """
    for wait in (0, 2, 5, 10):
        time.sleep(wait)
        res = _securityhub.batch_update_findings(
            FindingIdentifiers=[{"Id": finding["Id"], "ProductArn": finding["ProductArn"]}],
            Workflow={"Status": "NOTIFIED"},
            Note={"Text": "自動で通知しました(AR-3)", "UpdatedBy": "auto-notify"},
        )
        failed = res.get("UnprocessedFindings", [])
        if not failed:
            logger.info("ワークフローの状態を NOTIFIED にしました")
            return
        logger.warning("NOTIFIED にできませんでした(%s 秒後にやり直します):%s", wait, failed[0].get("ErrorMessage"))
    logger.error("NOTIFIED にできないまま終わりました。手で状態を変えてください(運用手順書 OP-20)")


def handler(event, _context):
    logger.info("受け取ったイベント:%s / %s", event.get("source"), event.get("detail-type"))
    if event.get("detail-type") == "Security Hub Findings - Imported":
        _handle_findings(event)
    else:
        _handle_api_call(event)
    return {"ok": True}
