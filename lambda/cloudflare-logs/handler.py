"""Cloudflare Access の認証のログを集める Lambda(P2-3、DOC-03 9章)

- 6時間ごとに、直近24時間分を Cloudflare の API から取る(3回続けて失敗しても取りこぼさない)
  GET /accounts/{account_id}/access/logs/access_requests(権限:Access: Audit Logs Read)
- Free プランでは Cloudflare に24時間しか残らないため、取りこぼさないよう間隔を短くしている
- ログ用 S3 に gzip の JSON Lines で保存する:cloudflare/access_requests/dt=YYYY-MM-DD/<実行時刻>.json.gz
  (記録の日付ごとにファイルを分ける。重なった分は Athena で ray_id で重複を除く)
- ページングの守り:result_info があれば総ページ数に従う。前のページと同じ並び(ray_id)が返ったら、
  ページの指定が効いていないとみなして失敗にする(同じ記録を延々と保存しないため)
- 失敗したら例外を投げる(Lambda の Errors の指標と、CloudWatch Logs の ERROR で分かる)
- トークンとメールアドレスはログに出さない
"""

import gzip
import json
import logging
import os
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

API = "https://api.cloudflare.com/client/v4"
PER_PAGE = int(os.environ.get("PER_PAGE", "100"))
MAX_PAGES = int(os.environ.get("MAX_PAGES", "100"))
WINDOW_HOURS = int(os.environ.get("WINDOW_HOURS", "24"))

_ssm = boto3.client("ssm")
_s3 = boto3.client("s3")


def _token():
    p = _ssm.get_parameter(Name=os.environ["TOKEN_PARAM"], WithDecryption=True)
    return p["Parameter"]["Value"]


def _iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _get(url, token):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310(宛先は固定の https)
        body = json.loads(r.read())
    if not body.get("success"):
        # エラーの中身(コードとメッセージ)だけを出す
        raise RuntimeError(f"Cloudflare API error: {body.get('errors')}")
    return body.get("result") or [], body.get("result_info") or {}


def fetch(account_id, token, since, until):
    records = []
    prev_ids = None
    for page in range(1, MAX_PAGES + 1):
        q = urllib.parse.urlencode({
            "since": _iso(since),
            "until": _iso(until),
            "direction": "asc",
            "per_page": PER_PAGE,
            "limit": PER_PAGE,
            "page": page,
        })
        result, info = _get(f"{API}/accounts/{account_id}/access/logs/access_requests?{q}", token)
        ids = [r.get("ray_id") for r in result]
        if result and ids == prev_ids:
            raise RuntimeError(f"page {page} returned the same records as page {page - 1}; paging is not working")
        prev_ids = ids
        records.extend(result)
        total_pages = info.get("total_pages")
        if total_pages is not None:
            if page >= int(total_pages):
                return records
        elif len(result) < PER_PAGE:
            return records
    # 上限まで来たら、取りこぼしがあるかもしれないので失敗にする
    raise RuntimeError(f"too many pages (>{MAX_PAGES}); some records may be missing")


def save(bucket, prefix, records, run_at):
    by_day = defaultdict(list)
    for r in records:
        day = (r.get("created_at") or _iso(run_at))[:10]
        by_day[day].append(r)
    keys = []
    for day, rows in sorted(by_day.items()):
        body = gzip.compress("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in rows).encode())
        key = f"{prefix}/dt={day}/{run_at.strftime('%Y%m%dT%H%M%SZ')}.json.gz"
        _s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="application/json", ContentEncoding="gzip",
                       ChecksumAlgorithm="SHA256")  # オブジェクトロックのバケットは、チェックサムが必須
        keys.append(key)
    return keys


def handler(event, context):
    run_at = datetime.now(timezone.utc).replace(microsecond=0)
    since = run_at - timedelta(hours=WINDOW_HOURS)
    records = fetch(os.environ["CLOUDFLARE_ACCOUNT_ID"], _token(), since, run_at)
    keys = save(os.environ["LOG_BUCKET"], os.environ["PREFIX"], records, run_at)
    denied = sum(1 for r in records if r.get("allowed") is False)
    logger.info(json.dumps({"since": _iso(since), "until": _iso(run_at), "records": len(records), "denied": denied, "files": len(keys)}))
    return {"records": len(records), "denied": denied, "files": len(keys)}
