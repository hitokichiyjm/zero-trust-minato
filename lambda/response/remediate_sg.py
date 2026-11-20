"""セキュリティグループの自動修復の Lambda(AR-1)

インターネット全体(0.0.0.0/0、::/0)に危険なポートを開けるルールが追加されたら、そのルールだけを削除して通知する。

安全策(DOC-03 8.3):
- 対象のアカウントの「修復用ロール」(SG のルールを消すことしかできない)を引き受けて操作する
- `auto-remediation=false` のタグが付いた SG は消さずに、通知だけする
- 消したルールの内容を通知に含め、必要なら作り直せるようにする(運用手順書 OP-21)
"""

import logging
import os

import boto3

import notify_lib

logger = logging.getLogger()
logger.setLevel(logging.INFO)

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
RISKY_PORTS = {int(p) for p in os.environ.get("RISKY_PORTS", "22,3389").split(",")}


def _ec2_for(account_id, region):
    role_arn = f"arn:aws:iam::{account_id}:role/{os.environ['REMEDIATION_ROLE_NAME']}"
    creds = boto3.client("sts").assume_role(RoleArn=role_arn, RoleSessionName="auto-remediation")["Credentials"]
    return boto3.client(
        "ec2",
        region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def _is_risky(rule):
    """インターネット全体に、危険なポート(またはすべてのポート)を開けているか。"""
    cidr = rule.get("CidrIpv4") or rule.get("CidrIpv6")
    if cidr not in OPEN_CIDRS:
        return False
    if rule.get("IpProtocol") == "-1":  # すべてのプロトコル・ポート
        return True
    low, high = rule.get("FromPort", -1), rule.get("ToPort", -1)
    return any(low <= p <= high for p in RISKY_PORTS)


def _describe(rule):
    cidr = rule.get("CidrIpv4") or rule.get("CidrIpv6")
    proto = "すべて" if rule.get("IpProtocol") == "-1" else rule.get("IpProtocol")
    ports = "すべて" if rule.get("IpProtocol") == "-1" else f"{rule.get('FromPort')}-{rule.get('ToPort')}"
    return f"{rule['SecurityGroupRuleId']}:プロトコル {proto}、ポート {ports}、送信元 {cidr}"


def handler(event, _context):
    d = event["detail"]
    if d.get("errorCode"):
        logger.info("操作自体が失敗しているため、何もしません")
        return {"ok": True, "action": "none"}

    account_id = d.get("recipientAccountId", event.get("account"))
    region = d.get("awsRegion", event.get("region"))
    group_id = d.get("requestParameters", {}).get("groupId")
    added_ids = [
        item.get("securityGroupRuleId")
        for item in d.get("responseElements", {}).get("securityGroupRuleSet", {}).get("items", [])
        if not item.get("isEgress")
    ]
    if not group_id or not added_ids:
        logger.info("対象の SG やルールが分からないため、何もしません")
        return {"ok": True, "action": "none"}

    ec2 = _ec2_for(account_id, region)
    rules = ec2.describe_security_group_rules(SecurityGroupRuleIds=added_ids)["SecurityGroupRules"]
    risky = [r for r in rules if _is_risky(r)]
    if not risky:
        return {"ok": True, "action": "none"}

    tags = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0].get("Tags", [])
    exempt = any(t["Key"] == "auto-remediation" and t["Value"].lower() == "false" for t in tags)

    who = d.get("userIdentity", {}).get("arn", "不明")
    base = [
        f"アカウント:{account_id}",
        f"リージョン:{region}",
        f"SG:{group_id}",
        f"変更した人:{who}",
        f"送信元 IP:{d.get('sourceIPAddress', '不明')}",
        "危険なルール:",
        *[f"  - {_describe(r)}" for r in risky],
    ]

    if exempt:
        notify_lib.send(
            "危険な SG のルールを検知(例外タグのため削除せず)",
            base + ["`auto-remediation=false` のタグがあるため、削除していません。例外が妥当か確認してください(OP-21)"],
            "HIGH",
        )
        return {"ok": True, "action": "notified-only"}

    ec2.revoke_security_group_ingress(GroupId=group_id, SecurityGroupRuleIds=[r["SecurityGroupRuleId"] for r in risky])
    logger.info("削除しました:%s", [r["SecurityGroupRuleId"] for r in risky])
    notify_lib.send(
        "危険な SG のルールを自動で削除しました(AR-1)",
        base + ["上のルールを削除しました。必要なら送信元を絞って、Terraform で作り直してください(OP-21)"],
        "ACTION",
    )
    return {"ok": True, "action": "revoked", "rules": [r["SecurityGroupRuleId"] for r in risky]}
