resource "aws_iam_role" "datadog_workflow_role" {
  count  = var.enable_datadog_role ? 1 : 0
  name = "DatadogWorkflowRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::464622532012:root" # Datadog account
        }
        Action    = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.datadog_external_id
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "invoke_block_user_lambda_role_policy" {
  count  = var.enable_datadog_role ? 1 : 0

  name = "AllowInvokeBlockIdentityCenterUserRolePolicy"
  role = aws_iam_role.datadog_workflow_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowInvokeBlockIdentityCenterUserLambda"
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = "arn:aws:lambda:${var.region}:${data.aws_caller_identity.current.account_id}:function:BlockIdentityCenterUser"
      }
    ]
  })
}