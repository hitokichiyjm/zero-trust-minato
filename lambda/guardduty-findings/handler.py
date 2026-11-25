"""GuardDuty の検知をログ用 S3 に保存する Lambda(P2-3、DOC-03 9章の方法 B)

- security(GuardDuty の委任管理者)の既定のバスに来る「GuardDuty Finding」のイベントを、
  log-archive のバスに転送し、ここで受け取る(メンバーの検知も委任管理者に集まる)
- 1つのイベントを1つのファイルにする:guardduty/findings/dt=YYYY-MM-DD/<検知のID>-<更新日時>.json
  (同じ検知の更新も、別のファイルとして残る)
- 失敗したら例外を投げる(EventBridge が再試行し、Lambda の Errors の指標で分かる)
"""

import json
import logging
import os
import re

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_s3 = boto3.client("s3")
_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def handler(event, context):
    d = event.get("detail") or {}
    finding_id = _SAFE.sub("_", str(d.get("id") or event.get("id") or "unknown"))
    updated = str(d.get("updatedAt") or event.get("time") or "")
    day = (updated or "1970-01-01")[:10]
    stamp = _SAFE.sub("", updated.replace(":", "").replace("-", "")) or "na"
    key = f"{os.environ['PREFIX']}/dt={day}/{finding_id}-{stamp}.json"
    _s3.put_object(
        Bucket=os.environ["LOG_BUCKET"],
        Key=key,
        Body=json.dumps(event, ensure_ascii=False).encode(),
        ContentType="application/json",
        ChecksumAlgorithm="SHA256",  # オブジェクトロックのバケットは、チェックサムが必須
    )
    logger.info(json.dumps({"type": d.get("type"), "severity": d.get("severity"), "key_day": day}))
    return {"saved": 1}
