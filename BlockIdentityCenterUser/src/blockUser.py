import boto3
import json
import os
import time
from datetime import datetime, timezone

identity_store_client = boto3.client('identitystore')
sso_admin_client = boto3.client('sso-admin')
def get_instance_arns():
    instance_arns = []
    try:
        response = sso_admin_client.list_instances()
        for instance in response['Instances']:
            instance_arn = instance['InstanceArn']
            instance_arns.append(instance_arn)
            print(f"Instance ARN: {instance_arn}")
    except Exception as e:
        print(f"Error listing SSO instances: {e}")
    return instance_arns

def get_user_id(username, identity_store_id):
    """Retrieve the user ID for a given username."""
    response = identity_store_client.list_users(
        IdentityStoreId=identity_store_id,  
        Filters=[
            {
                'AttributePath': 'UserName',
                'AttributeValue': username
            },
        ]
    )
    users = response['Users']
    if not users:
        raise ValueError("User not found")
    return users[0]['UserId']

def list_accounts_for_provisioned_permission_set(instance_arn, permission_set_arn):
    """List all accounts for a provisioned permission set."""
    accounts = []
    paginator = sso_admin_client.get_paginator('list_accounts_for_provisioned_permission_set')
    page_iterator = paginator.paginate(
        InstanceArn=instance_arn,
        PermissionSetArn=permission_set_arn
    )
    for page in page_iterator:
        accounts.extend(page['AccountIds'])
    return accounts

def provision_permission_set(instance_arn, permission_set_arn, account_id):
    """Provision a permission set to an account."""
    try:
        response = sso_admin_client.provision_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn,
            TargetId=account_id,
            TargetType='AWS_ACCOUNT'
        )
        request_id = response['PermissionSetProvisioningStatus']['RequestId']
        wait_for_provisioning(instance_arn, request_id)
        print(f"Provisioned permission set to account {account_id}")
    except Exception as e:
        print(f"An error occurred when provisioning the permission set: {e}")

def wait_for_provisioning(instance_arn, request_id):
    """Wait for the provisioning to complete."""
    status = 'IN_PROGRESS'
    while status == 'IN_PROGRESS':
        time.sleep(5)  # Poll every 5 seconds
        response = sso_admin_client.describe_permission_set_provisioning_status(
            InstanceArn=instance_arn,
            ProvisionPermissionSetRequestId=request_id
        )
        status = response['PermissionSetProvisioningStatus']['Status']
        if status == 'FAILED':
            raise Exception(f"Provisioning failed: {response['PermissionSetProvisioningStatus']['FailureReason']}")
    print("Provisioning completed.")

def update_permission_sets(user_id, user_name, instance_arn, action):
    """Update all Permission Sets by either blocking or unblocking a user."""
    block_statement_id = "PotentialCompromise"

    # Define the blocking statement
    current_time = datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    block_statement = {
        "Sid": block_statement_id,
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
        "Condition": {
            "StringEquals": {
                "identitystore:userId": user_id
            },
            "DateLessThan": {
                "aws:TokenIssueTime": current_time
            }
        }
    }

    # List all permission sets
    permission_sets = sso_admin_client.list_permission_sets(InstanceArn=instance_arn)['PermissionSets']

    for permission_set in permission_sets:
        # Retrieve the current inline policy
        policy_response = sso_admin_client.get_inline_policy_for_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set
        )
        if policy_response['InlinePolicy'] == '':
            current_policy = json.loads('{"Version": "2012-10-17", "Statement": []}')
        else:
            current_policy = json.loads(policy_response['InlinePolicy'])
        if action == "block":
            # Append the block statement if not already present
            if not any(stmt.get("Sid") == block_statement_id for stmt in current_policy.get("Statement", [])):
                current_policy['Statement'].append(block_statement)
                print(f"Blocking access for {user_name} on PermissionSet {permission_set}.")
        elif action == "unblock":
            # Remove the block statement if it exists
            current_policy['Statement'] = [stmt for stmt in current_policy.get("Statement", []) if stmt.get("Sid") != block_statement_id]
            print(f"Unblocking access for {user_name} on PermissionSet {permission_set}.")

        # Update the permission set with the modified policy
        if current_policy['Statement'] == []:
            try:
                sso_admin_client.delete_inline_policy_from_permission_set(
                    InstanceArn=instance_arn,
                    PermissionSetArn=permission_set
                )
            except Exception as e:
                print(f"An error occurred when deleting the inline policy: {e}")
        else:
            try:
                sso_admin_client.put_inline_policy_to_permission_set(
                    InstanceArn=instance_arn,
                    PermissionSetArn=permission_set,
                    InlinePolicy=json.dumps(current_policy)
                )
            except Exception as e:
                print(f"An error occurred when adding the inline policy: {e}")
        # Provision the permission set to all relevant accounts
        account_ids = list_accounts_for_provisioned_permission_set(instance_arn, permission_set)
        for account_id in account_ids:
            provision_permission_set(instance_arn, permission_set, account_id)

def lambda_handler(event, context):
    identity_store_id = os.environ.get("IDENTITY_STORE_ID")
    user_name = event["user_name"]
    if event["block"] is True:
        action = "block"
    else:
        action = "unblock"
    try:
        instance_arns = get_instance_arns()
        user_id = get_user_id(user_name, identity_store_id)
        for instance_arn in instance_arns:
            update_permission_sets(user_id, user_name, instance_arn, action)
        print(f"All Permission Sets {action}ed successfully for {user_name}.")
    except Exception as e:
        print(f"An error occurred: {e}")
