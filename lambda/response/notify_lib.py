"""通知の共通処理:SNS(メール)と Slack(Webhook)に送る。

- SNS には必ず送る(確実に届く経路)
- Slack は、SSM Parameter Store に Webhook の URL が登録されていれば送る
  (URL は秘密情報のため、コードや環境変数には書かない)
"""

import json
import logging
import os
import urllib.request

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_sns = boto3.client("sns")
_ssm = boto3.client("ssm")
_slack_url_cache = {"loaded": False, "url": None}


def _slack_url():
    """Slack の Webhook URL を SSM から読む(1回だけ読み、以後は使い回す)。"""
    if _slack_url_cache["loaded"]:
        return _slack_url_cache["url"]
    _slack_url_cache["loaded"] = True
    name = os.environ.get("SLACK_WEBHOOK_PARAM", "")
    if not name:
        return None
    try:
        res = _ssm.get_parameter(Name=name, WithDecryption=True)
        _slack_url_cache["url"] = res["Parameter"]["Value"]
    except _ssm.exceptions.ParameterNotFound:
        logger.info("Slack の Webhook URL が未登録のため、メールだけに送ります")
    return _slack_url_cache["url"]


def send(title, lines, severity="INFO"):
    """title と本文の行(lines)を、SNS と Slack に送る。"""
    icon = {"CRITICAL": ":rotating_light:", "HIGH": ":warning:", "ACTION": ":white_check_mark:"}.get(severity, ":information_source:")
    body = "\n".join(lines)

    _sns.publish(
        TopicArn=os.environ["SNS_TOPIC_ARN"],
        Subject=f"[{severity}] {title}"[:100],
        Message=body,
    )

    url = _slack_url()
    if url:
        payload = {"text": f"{icon} *[{severity}] {title}*\n{body}"}
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as res:  # nosec B310: URL は管理者が登録した Slack の Webhook だけ
                logger.info("Slack に送信しました: %s", res.status)
        except Exception:  # Slack が失敗しても、SNS には送れているので処理は続ける
            logger.exception("Slack への送信に失敗しました")
