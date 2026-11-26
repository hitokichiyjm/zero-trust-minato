"""外部委託者の期限切れの Lambda(FR-ID-06、UC-2、DOC-03 5.3。P2-4)

- 毎日 0:10(日本時間)に動く
- 契約の終了日(expires)の日以降になった外部委託者を、g-contractor のグループから外す(利用者そのものは消さない)
- 外した人がいれば、security の集約用バスにイベントを送る(notify の Lambda がメールで知らせる)
- 期限と利用者の ID は、Terraform(identity スタックの locals)から環境変数で受け取る
- ログには利用者名と件数だけを出す(メールアドレスは扱わない)
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

JST = timezone(timedelta(hours=9))

_ids = boto3.client("identitystore")
_events = boto3.client("events")


def _today(event):
    """試しのときだけ、event の as_of(YYYY-MM-DD)で「今日」を替えられる(手で呼び出せるのは管理者だけ)"""
    as_of = (event or {}).get("as_of")
    if as_of:
        return datetime.strptime(as_of, "%Y-%m-%d").date()
    return datetime.now(JST).date()


def _membership_id(store_id, group_id, user_id):
    try:
        res = _ids.get_group_membership_id(IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": user_id})
        return res["MembershipId"]
    except _ids.exceptions.ResourceNotFoundException:
        return None


def handler(event, context):
    store_id = os.environ["IDENTITY_STORE_ID"]
    group_id = os.environ["GROUP_ID"]
    contractors = json.loads(os.environ["CONTRACTORS"])
    today = _today(event)

    removed, already, active = [], [], []
    for name, c in sorted(contractors.items()):
        expires = datetime.strptime(c["expires"], "%Y-%m-%d").date()
        if today < expires:
            active.append(name)
            continue
        mid = _membership_id(store_id, group_id, c["user_id"])
        if mid is None:
            already.append(name)
            continue
        _ids.delete_group_membership(IdentityStoreId=store_id, MembershipId=mid)
        removed.append({"user_name": name, "expires": c["expires"]})

    if removed:
        res = _events.put_events(Entries=[{
            "Source": os.environ["EVENT_SOURCE"],
            "DetailType": "Contractor Access Expired",
            "Detail": json.dumps({"group": os.environ.get("GROUP_NAME", ""), "removed": removed, "date": today.isoformat()}, ensure_ascii=False),
            "EventBusName": os.environ["EVENT_BUS_ARN"],
        }])
        if res.get("FailedEntryCount"):
            raise RuntimeError(f"failed to send the notification event: {res['Entries']}")

    result = {"date": today.isoformat(), "as_of_override": bool((event or {}).get("as_of")), "removed": [r["user_name"] for r in removed], "already_removed": already, "active": len(active)}
    logger.info(json.dumps(result, ensure_ascii=False))
    return result
