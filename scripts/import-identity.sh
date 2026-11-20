#!/usr/bin/env bash
# P0 で手動で作った Identity Center の設定を、terraform/identity に取り込む(1回だけ実行する)。
# ID はその場で AWS から調べるため、リポジトリにアカウントIDなどを書かずに済む。
#
# 使い方(terraform/identity で terraform init した後):
#   AWS_PROFILE=minato-mgmt bash scripts/import-identity.sh <Identity Center のユーザー名>
set -euo pipefail

USER_NAME="${1:?Identity Center のユーザー名を指定してください}"
cd "$(dirname "$0")/../terraform/identity"

INST=$(aws sso-admin list-instances --query 'Instances[0].InstanceArn' --output text)
IDS=$(aws sso-admin list-instances --query 'Instances[0].IdentityStoreId' --output text)
MGMT=$(aws organizations describe-organization --query 'Organization.MasterAccountId' --output text)

GROUP_ID=$(aws identitystore list-groups --identity-store-id "${IDS}" \
  --filters AttributePath=DisplayName,AttributeValue=g-it-admin --query 'Groups[0].GroupId' --output text)
USER_ID=$(aws identitystore list-users --identity-store-id "${IDS}" \
  --filters AttributePath=UserName,AttributeValue="${USER_NAME}" --query 'Users[0].UserId' --output text)
MEMBERSHIP_ID=$(aws identitystore get-group-membership-id --identity-store-id "${IDS}" \
  --group-id "${GROUP_ID}" --member-id UserId="${USER_ID}" --query MembershipId --output text)

PS_ARN=""
for ps in $(aws sso-admin list-permission-sets --instance-arn "${INST}" --query 'PermissionSets[]' --output text); do
  name=$(aws sso-admin describe-permission-set --instance-arn "${INST}" --permission-set-arn "${ps}" --query 'PermissionSet.Name' --output text)
  if [ "${name}" = "AdministratorAccess" ]; then PS_ARN="${ps}"; fi
done
if [ -z "${PS_ARN}" ]; then echo "許可セット AdministratorAccess が見つかりません"; exit 1; fi

ADMIN_POLICY="arn:aws:iam::aws:policy/AdministratorAccess"

terraform import 'aws_identitystore_group.this["g-it-admin"]' "${IDS}/${GROUP_ID}"
terraform import 'aws_identitystore_group_membership.admin' "${IDS}/${MEMBERSHIP_ID}"
terraform import 'aws_ssoadmin_permission_set.this["AdministratorAccess"]' "${PS_ARN},${INST}"
terraform import 'aws_ssoadmin_managed_policy_attachment.this["AdministratorAccess:AdministratorAccess"]' "${ADMIN_POLICY},${PS_ARN},${INST}"
terraform import 'aws_ssoadmin_account_assignment.this["g-it-admin:AdministratorAccess:management"]' \
  "${GROUP_ID},GROUP,${MGMT},AWS_ACCOUNT,${PS_ARN},${INST}"

echo "取り込みが終わりました。terraform plan で、削除や作り直しがないことを確かめてください。"
