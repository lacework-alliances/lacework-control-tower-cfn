# Lacework AWS Control Tower Customization

![Lacework](https://user-images.githubusercontent.com/6440106/152378397-90c862e9-19fb-4427-96d0-02ca6c87f4dd.png)

## Overview
With Lacework and AWS Control Tower, enrolling a new AWS account now means security best practices and monitoring are automatically applied consistently across your organization. Account administrators can automatically add Lacework's security auditing and monitoring to AWS accounts seamlessly. All the required Lacework and AWS account configurations that allow access to AWS configuration and CloudTrail logs are managed for you by Lacework’s AWS Control Tower integration.

## How It Works
The Lacework AWS Control Tower integration audits and monitors AWS accounts in your [AWS Control Tower Landing Zone](https://aws.amazon.com/controltower/features/#Landing_Zone). Your Landing Zone is your multi-account environment for which you can apply your governance, auditing and monitoring. On initial setup, the Lacework AWS Control Tower integration creates a new cross-account role in the Log Archive account and a new SQS queue is set up in the Audit account. The SQS queue allows Lacework to receive notifications of new audit logs in S3 from the centralized CloudTrail that collects activity from all accounts. Lacework processes these logs for behavior analysis for all AWS accounts.

For new AWS accounts in your organization, [AWS Control Tower Account Factory](https://aws.amazon.com/controltower/features/#Account_Factory) enables easy onboarding of new and existing AWS accounts which triggers the Lacework integration through a new account lifecycle event. A Lambda function launches a stack instance that creates a new cross-account role and allows Lacework to monitor the account via AWS APIs. The combination of CloudTrail log analysis and AWS API access allows Lacework to check your cloud activity and AWS configuration to detect security misconfigurations and anomalous behavior.

![control_tower_architecture-8f93f8a8217035f89e7651e648608055](https://user-images.githubusercontent.com/6440106/154098553-5a2b4dd9-dcc8-4cd0-a610-33ef8d80eba0.png)

### Setup Flow

1. The Administrator applies Lacework's main Control Tower Integration template in Cloudformation for the initial setup in the AWS Control Tower Management account.
2. This template provisions all resources which includes a stack set, roles & permissions, Lambda functions, SQS queues and EventBridge rule.
3. Via LaceworkSetupFunction Lambda, a new cross-account role is set up in the Log Archive account and a new SQS queue is set up in the Audit account. The SQS queue allows Lacework to receive notifications of new audit logs in S3 from the centralized CloudTrail that collects activity from all accounts. Lacework processes these logs for behavior analysis for all AWS accounts.
4. The LaceworkSetupFunction acquires the initial Lacework access token.
5. The LaceworkSetupFunction provisions any existing ACTIVE AWS accounts by sending an SNS message to the StackSet Lambda Function if specified with the Monitor Existing Accounts option.
6. The LaceworkAccountFunction Lambda creates a new Stack instance(s) for the account(s).
7. The Stack instance creates a new cross-account role and allows Lacework to monitor the account via AWS APIs.
8. The Stack instance notifies Lacework of the new account through an SNS custom resource notification, LaceworkSNSCustomResource. The account is created in Lacework.
9. A scheduled event rule periodically triggers the LaceworkAuthFunction Lambda to acquire a temporary access token from Lacework.

### New Account Flow

1. A new AWS account triggers a Control Tower lifecycle event which is picked up by the EventBridge rule.
2. The EventBridge rule triggers the LaceworkAccountFunction Lambda to create a new Stack instance for the account.
3. The LaceworkAccountFunction Lambda creates a new Stack instance(s) for the account(s).
4. The Stack instance creates a new cross-account role and allows Lacework to monitor the account via AWS APIs.
5. The Stack instance notifies Lacework of the new account through an SNS custom resource notification, LaceworkSNSCustomResource. This sends an SNS notification to Lacework and the account is created in Lacework’s platform.

## Prerequisites
You need the following prerequisites to implement the Lacework AWS Control Tower integration.

- AWS Control Tower with a Landing Zone. For information about setting up an AWS Control Tower landing zone, see [Getting Started with AWS Control Tower in the AWS Control Tower User Guide](https://docs.aws.amazon.com/controltower/latest/userguide/getting-started-with-control-tower.html).
- Administrator privileges in the AWS Control Tower management account.
- A Lacework Cloud Security Platform SaaS account.

## Lacework and AWS Organization Support
The Lacework AWS Control Tower integration supports the Lacework Organizations feature and AWS Organizations mapping. Two scenarios are supported:

### All AWS Accounts to a Single Lacework Sub-Account
In the CloudFormation stack parameters, you can specify a Lacework sub-account for which all AWS accounts will be added. This is specified in the **Single Sub-Account Configuration** section in the **Lacework Sub-Account Name** field (see below).
### AWS Organizations to Lacework Sub-Account Mapping
In the CloudFormation stack parameters, you can specify a comma-separated list of AWS organization names that match Lacework sub-account names. AWS accounts will be added to the appropriate Lacework sub-accounts based on this AWS organization-to-Lacework sub-account name mapping. AWS organization names and Lacework sub-account names must match. AWS accounts not in the specified organizations will not be added to Lacework. This is specified in the **Organization Configuration** section in the **AWS Organizations to Lacework Sub-Account Names** field (see below).

When creating AWS organizations, creating AWS accounts or moving AWS accounts across organizations, ensure that you use the [recommended AWS Control Tower methods](https://docs.aws.amazon.com/controltower/latest/userguide/provision-and-manage-accounts.html). This will ensure that Lacework monitors the correct AWS accounts. Making updates to AWS accounts outside of AWS Control Tower may cause issues.

## Installing the Lacework AWS Control Tower Integration

### 1. Generate a Lacework API Access Key

If using Lacework and AWS Organization Support, ensure that you are generating an API key from the Org Admin Lacework account.
1. In your console, go to **Settings > API Keys**.
2. Click on the **Create New** button in the upper right to create a new API key.
3. Provide a **name** and **description** and click Save.
4. Click the download button to download the API keys file.
5. Copy the **keyId** and **secret** from this file.

### 2. Login into your AWS Control Tower Management Account

1. Login in to AWS Control Tower management account.
2. Select the AWS region where your AWS Control Tower is deployed.

### 3. Deploy the Lacework AWS Control Tower Integration with CloudFormation

1. Click on the following Launch Stack button to go to your CloudFormation console and launch the AWS Control Integration template.

   [![Launch](https://user-images.githubusercontent.com/6440106/153987820-e1f32423-1e69-416d-8bca-2ee3a1e85df1.png)](https://console.aws.amazon.com/cloudformation/home?#/stacks/create/review?templateURL=https://lacework-alliances.s3.us-west-2.amazonaws.com/lacework-control-tower-cfn/templates/control-tower-integration.template.yml)

   For most deployments, you only need the Basic Configuration parameters.
   ![basic_configuration](https://user-images.githubusercontent.com/6440106/154780415-dba58c69-aec2-49ee-b8e9-d98d7a8f9efc.png)
2. Specify the following Basic Configuration parameters:
    * Enter a **Stack name** for the stack.
    * Enter **Your Lacework URL**.
    * Enter your **Lacework Access Key ID** and **Secret Key** that you copied from your previous API Keys file.
    * For **Capability Type**, the recommendation is to use **CloudTrail+Config** for the best capabilities.
    * Choose whether you want to **Monitor Existing Accounts**. This will set up monitoring of ACTIVE existing AWS accounts.
    * Enter the name of your **Existing AWS Control Tower CloudTrail Name**.
    * If your CloudTrail S3 logs are encrypted, specify the **KMS Key Identifier ARN**. Ensure that KMS Key Policy is updated to allow access to the Log account cross-account role used by Lacework. Add the following to the Key Policy.
   ```
   "Sid": "Allow Lacework to decrypt logs",
   "Effect": "Allow",
   "Principal": {
   "AWS": [
   "arn:aws:iam::<log-archive-account-id>:role/<lacework-account-name>-laceworkcwssarole"
   ]
   },
   "Action": [
   "kms:Decrypt"
   ],
   "Resource": "*"
   ```
   ![control_tower_kms_key_policy.png](https://docs.lacework.com/assets/images/control_tower_kms_key_policy-ba8f68668bb3cadc57c74364a5a657d3.png)
    * Update the Control Tower **Log Account Name** and **Audit Account Name** if necessary.
    * If using AWS organizations to Lacework sub-account mapping, specify a comma-separated lists of organization names in the **Organization Configuration** section in the **AWS Organizations to Lacework Sub-Account Names** field. AWS accounts will be added to the appropriate Lacework sub-accounts based on this AWS organization-to-Lacework sub-account name mapping. AWS organization names and Lacework sub-account names must match. AWS accounts not in the specified organizations will not be added to Lacework.
      
   ![organization_configuration](https://user-images.githubusercontent.com/6440106/154780412-7543afb2-f84e-42e4-b31d-0b0cc2d6c55a.png)
    * If using a single Lacework sub-account for all AWS accounts, specify a Lacework sub-account for which all AWS accounts will be added. This is specified in the **Single Sub-Account Configuration** section in the **Lacework Sub-Account Name** field.
      
   ![sub_account_configuration](https://user-images.githubusercontent.com/6440106/154780411-50b270b5-4246-4e12-acb1-b1d4997b5671.png)
3. Click **Next** through to your stack **Review**.
4. Accept the AWS CloudFormation terms and click **Create stack**.

### 4. CloudFormation Progress

1. Monitor the progress of the CloudFormation deployment. It takes several minutes for the stack to create the resources that enable the Lacework AWS Control Tower Integration.
2. When successfully completed, the stack shows CREATE_COMPLETE.

### 5. Validate the Lacework AWS Control Tower Integration

1. Login to your Lacework Cloud Security Platform console.
2. Go to **Settings > Cloud Accounts**.
3. You should see a list of AWS accounts that are now being monitored by Lacework. The **Cloud Account** column values correspond to the AWS Account IDs.

## Remove the Lacework AWS Control Tower Integration

To remove the Lacework AWS Control Tower Integration, simply delete the main stack. All CloudFormation stacksets, stack instances, and Lambda functions will be deleted. **Note:** Lacework will no longer monitor your AWS cloud environment.

## Troubleshooting
The following sections provide guidance for resolving issues with deploying the Lacework AWS Control Tower integration.

### Common Issues

* Ensure the **Existing AWS Control Tower CloudTrail Name** is correct. You can verify this on your AWS CloudTrail Dashboard.
* Ensure that your **Log Archive** and **Audit** account names are correct and these accounts are ACTIVE.
* If you are using Lacework Organizations to manage your accounts, specify the correct sub-account name, API key ID and secret key.
* If Lacework returns a S3 access error for the CloudTrail account and a KMS key is used, ensure that KMS Key Policy is updated to allow access to the Log account cross-account role used by Lacework.
```
"Sid": "Allow Lacework to decrypt logs",
"Effect": "Allow",
"Principal": {
    "AWS": [
        "arn:aws:iam::<log-archive-account-id>:role/<lacework-account-name>-laceworkcwssarole"
    ]
},
"Action": [
    "kms:Decrypt"
],
"Resource": "*"
```

### Events and Logs

#### CloudFormation Events

You can monitor the CloudFormation events for the Lacework AWS Control Tower integration stack. Events may reveal issues with resource creation. The Lacework AWS Control Tower integration stack launches a main stack and three stacksets:

**Main Deployment Stack:**
* **control-tower-integration.template.yml** - Main stack that deploys all resources: IAM roles, access token credentials, IAM roles, SQS queues, Lambda functions and the stacksets below.

**Centralized CloudTrail Cloud Account in Lacework:** (Applied once during initial deployment)
* **lacework-aws-ct-audit.template.yml** -> **Lacework-Control-Tower-CloudTrail-Audit-Account-**_Lacework account_ - Creates a stack instance in the Audit account.
* **lacework-aws-ct-log.template.yml** -> **Lacework-Control-Tower-CloudTrail-Log-Account-**_Lacework account_ - Creates a stack instance in the Log account.

**Config Cloud Account in Lacework:** (Applied for each AWS account)
* **lacework-aws-cfg-member.template.yml** -> **Lacework-Control-Tower-Config-Member-**_Lacework account_ - Creates a stack instance in each AWS account.

Examining these stacksets for operation results, stack instance results and parameters may also provide debug information.

#### Lambda Function CloudWatch Logs

Two main Lambda functions are used to manage accounts. LaceworkSetupFunction manages the initial deployment of the integration. LaceworkAccountFunction manages enrolling AWS accounts into Lacework. Both Lambda functions provide extensive debug messages that can be seen in their respective CloudWatch log streams. These logs can be exported and provided to the support team.

![AWS Control Tower CloudFormation Lambda](https://docs.lacework.com/assets/images/aws-control-tower-coudformation-lambda-b200f53d9aa57d4b38f7b1ab09a6b23c.png)

![cloudwatch](https://user-images.githubusercontent.com/6440106/153986709-96988d28-3996-4450-9aa5-0c6218585b0f.png)

#### Lacework API Access Keys
The AWS Control Tower uses the Lacework API to manage the cloud accounts. The API Access Key, Secret and Access Token are stored using AWS Secrets Manager. The secret name is _LaceworkApiCredentials_. The Auth Lambda function periodically refreshes the access token.

## FAQ

* Can I individually choose which accounts are added to Lacework within AWS Control Tower?

Currently, this is not possible due to AWS Control Tower limitations. When enrolling an account with Account Factory, there isn't an option to choose which integrations are applied.

* How does Lacework integrate with AWS Control Tower's CloudTrail?

With AWS Control Tower, a centralized AWS CloudTrail trail is used. All cloud user and API activity are logged to this single trail. Lacework will monitor all cloud activity from this trail.

## Reference Documentation
- [Support docs on docs.lacework.com](https://docs.lacework.com/aws-config-and-cloudtrail-integration-with-aws-control-tower-using-cloudformation#troubleshooting)
- [Implementation Guide on AWS](https://d1.awsstatic.com/Marketplace/solutions-center/downloads/AWSMP-CT-Implementation-Guide-Lacework-Multi-Account-Security.pdf)
- [Datasheet](https://d1.awsstatic.com/Marketplace/solutions-center/downloads/AWSMP-CT-Datasheet-Lacework-Multi-Account-SEC.pdf)
- [AWS Control Tower Getting Started](https://docs.aws.amazon.com/controltower/latest/userguide/getting-started-with-control-tower.html)
- [Demo Video](https://drive.google.com/file/d/1bmSHkDKQOsKvErW7_14w5SmFcloUmc43/view?usp=sharing)