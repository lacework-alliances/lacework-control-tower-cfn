# Lacework AWS Control Tower Customization

![Lacework](https://user-images.githubusercontent.com/6440106/152378397-90c862e9-19fb-4427-96d0-02ca6c87f4dd.png)

## Overview
Lacework's AWS Control Tower Customization enables a seamless AWS account onboarding experience with the Lacework platform. Account administrators can automatically add Lacework's security auditing and monitoring to new AWS accounts during account creation. All the required Lacework and AWS account configuration that allows access to AWS configuration and CloudTrail logs are managed for you by this AWS Control Tower Customization.

## Architecture
![Architecture](https://drive.google.com/uc?export=view&id=17sbG56iMDkwxWXkhKCBXF46lWdoGPFdR)

### Setup Flow

1. The Administrator applies Lacework's main Control Tower Integration template in Cloudformation for the initial setup.
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

## Building and Uploading with Make

1. Check the Makefile in the project directory and ensure the KEY_PREFIX and DATASET values are set correctly. These reflect the S3 and Honeycomb properties.
2. In this project directory, run `make HONEY_KEY=<HONEYCOMB_SECRET>` to package the Lambda functions. <HONEYCOMB_SECRET> is the Honeycomb API token.
3. Run `make upload` to upload the Lambda packages and CloudFormation templates.
