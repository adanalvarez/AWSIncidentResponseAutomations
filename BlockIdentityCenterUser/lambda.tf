module "lambda_function" {
  source        = "terraform-aws-modules/lambda/aws"
  version       = "6.5.0"
  function_name = "BlockIdentityCenterUser"
  description   = "Lambda to block users from Identity Center via inline policies"
  handler       = "blockUser.lambda_handler"
  runtime       = "python3.11"
  source_path = "src/"
  timeout     = 120
  tags = {
    Name = "BlockIdentityCenterUser"
  }
  attach_policy_json = true
  policy_json = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
            "Effect": "Allow",
            "Action": [
                "sso:ListInstances",
                "sso:ListPermissionSets",
                "sso:GetInlinePolicyForPermissionSet",
                "sso:PutInlinePolicyToPermissionSet",
                "sso:DeleteInlinePolicyFromPermissionSet",
                "sso:ListAccountsForProvisionedPermissionSet",
                "sso:ProvisionPermissionSet",
                "sso:DescribePermissionSetProvisioningStatus",
                "identitystore:ListUsers",
                "iam:GetRole",
                "iam:ListAttachedRolePolicies",
                "iam:PutRolePolicy"
            ],
            "Resource": "*"
        }
    ]
  })
  environment_variables = {
    IDENTITY_STORE_ID = var.identity_store_id
  }
}