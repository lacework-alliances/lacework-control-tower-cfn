# Lacework AWS Control Tower Developer Guide

## Requirements

- AWS Account - Current development uses the lacework-alliances AWS account.
- AWS CLI - The AWS CLI must be installed and configured with a user that can push files to S3 buckets.
- Python3 - Python3 and Pip3 should be installed.
- AWS Control Tower - [AWS Control Tower](https://docs.aws.amazon.com/controltower/latest/userguide/getting-started-with-control-tower.html) should be enabled on the AWS account.
- Email Service - AWS Control Tower uses federated email login. You need to create email accounts to test multiple accounts.

## Directory Structure and Files
```
.
├── functions
│   ├── packages (zipped lambda functions)
│   │   ├── account
│   │   │   └── LaceworkCTAccount.zip 
│   │   ├── auth
│   │   │   └── LaceworkCTAuth.zip 
│   │   └── setup 
│   │       └── LaceworkCTSetup.zip 
│   └── source (lambda source code and nested makefiles)
│       ├── account
│       │   ├── Makefile 
│       │   ├── requirements.txt 
│       │   └── account.py 
│       ├── auth
│       │   ├── Makefile 
│       │   ├── requirements.txt 
│       │   └── auth.py 
│       └── setup 
│           ├── Makefile 
│           ├── requirements.txt 
│           └── setup.py 
├── templates (cloudformation templates)
│   ├── control-tower-integration.template.yml
│   ├── lacework-aws-cfg-member.template.yml
│   ├── lacework-aws-ct-audit.template.yml
│   └── lacework-aws-ct-log.template.yml
└── Makefile (master makefile)

```

## Set Up AWS Control Tower
Follow these instructions to set up an AWS Control Tower Landing Zone. You must have access to an email service in order to create email accounts. As new AWS accounts are created, you must provide a valid email address to complete the setup.

[AWS Control Tower Landing Zone Set Up](https://docs.aws.amazon.com/controltower/latest/userguide/getting-started-with-control-tower.html#step-two)

## Lambda Functions
- **Setup** - The Setup function is run when the control-tower-integration.template.yml stack is created. It does the following:
    * Sets up the initial access token and stores it using AWS secrets manager.
    * Creates the lacework-aws-cfg-member.template.yml, lacework-aws-ct-audit.template.yml and lacework-aws-ct-log.template.yml stacksets.
    * Executes lacework-aws-ct-audit.template.yml and lacework-aws-ct-log.template.yml stack instances for the Audit and Log Archive account respectively.
    * Adds the Lacework CloudTrail cloud account using the AWS Control Tower centralized CloudTrail S3 bucket.
    * If "Monitor existing accounts" is chosen, executes lacework-aws-cfg-member.template.yml stack instances for all existing AWS accounts. This adds Lacework Config cloud account for each AWS Account.
    * Sends Honeycomb telemetry.
- **Account** - The Account function is executed when an AWS Control Tower lifecycle event for a new AWS Account enrollment. This executes a lacework-aws-cfg-member.template.yml stack instance for the enrolled AWS account. This adds a Lacework Config cloud account for this AWS Account.
- **Auth** - This function periodically checks the Lacework access token for expiration and refreshes it if necessary.

## CloudFormation Templates
- **control-tower-integration.template.yml** - This is the master CloudFormation template and sets up all the initial resources: Lambda functions, roles, policies, SNS and event rules.
- **lacework-aws-cfg-member.template.yml** - This template closely resembles the standard Lacework configuration template and enables a Lacework Config type cloud account.
- **lacework-aws-ct-audit.template.yml** - This template sets up an SQS queue in the Audit AWS account where the AWS Control Tower CloudTrail SNS topic resides. Lacework receives CloudTrail update messages from the SQS queue.
- **lacework-aws-ct-log.template.yml** - This template configures CloudTrail S3 bucket access in the Log Archive account where this bucket resides.

## Lacework Control Tower Public S3 Buckets
Released Lambda packages and templates are placed in the following S3 bucket. Customers deploy the solution from this bucket.

```
s3://lacework-alliances/lacework-control-tower-cfn/
   ├── lambda/
   │   ├── LaceworkCTAccount.zip
   │   ├── LaceworkCTAuth.zip
   │   └── LaceworkCTSetup.zip
   └── templates/
       ├── control-tower-integration.template.yml
       ├── lacework-aws-cfg-member.template.yml
       ├── lacework-aws-ct-audit.template.yml
       └── lacework-aws-ct-log.template.yml
```

## Honeycomb Telemetry
The Setup Lambda function sends telemetry to two Honeycomb datasets, _lacework-alliances-prod_ or _lacework-alliances-dev_. This is configured in the master Makefile using the **DATASET** variable. A Honeycomb API key must be passed during the make build:

``
make HONEY_KEY=xxxxx
``

This API key is then passed to setup.py during the make build process.

## Building and Uploading
The master Makefile at the root executes the processing and packaging of the Lambda functions. Additionally, it can upload the Lambda packages and the templates to the configured S3 bucket. In the Makefile, configure the S3 parameters via the following variables.

```
BUCKET_PREFIX := lacework-alliances
KEY_PREFIX := lacework-control-tower-cfn
PACKAGES_PREFIX := lambda/
CFT_PREFIX := templates
CFT_DIR := templates
```
To build and upload, execute the following make commands.

```
make HONEY_KEY=xxxxx
make upload
```

## Dev, Test and Release Workflow

### Dev & Test
1. Make your code changes.
2. Update the master Makefile to change KEY_PREFIX and DATASET variables for testing. Change KEY_PREFIX to point to a test folder. Change DATASET to use the _lacework-alliances-dev_ Honeycomb dataset.
```
KEY_PREFIX := lacework-control-tower-cfn-test
DATASET := lacework-alliances-dev
```
3. Run _make_ and _make upload_ to upload your Lambda functions and templates for testing.
```
make HONEY_KEY=xxxxx
make upload
```
4. Go to your CloudFormation console and specify the control-tower-integration.template.yml in your S3 test folder location.
5. When entering the CloudFormation stack parameters, ensure **that the _Cloudformation S3 Key Prefix_ parameter is updated for the same test folder**.
6. Execute the stack.
7. Verify that the Lacework CloudTrail cloud account is created.
8. Verify that existing AWS accounts are created in Lacework as Config cloud accounts.
9. Go to Account Factory in AWS Control Tower and [enroll a new account](https://docs.aws.amazon.com/controltower/latest/userguide/enrollment-steps.html) (use a new email).
10. Verify that a new Lacework Config cloud account is created.

### Release
1. Update the master Makefile to change KEY_PREFIX and DATASET variables for releasing. Change KEY_PREFIX to point the release folder. Change DATASET to use the _lacework-alliances-prod_ Honeycomb dataset.
```
KEY_PREFIX := lacework-control-tower-cfn
DATASET := lacework-alliances-prod
```
3. Run _make_ and _make upload_ to upload your Lambda functions and templates for release.
```
make HONEY_KEY=xxxxx
make upload
```

## Troubleshooting

#### CloudFormation Events

You can monitor the CloudFormation events for the Lacework AWS Control Tower integration stack. Events may reveal issues with resource creation. The Lacework AWS Control Tower integration stack launches three stacksets:
* Lacework-Control-Tower-CloudTrail-Audit-Account-_Lacework account_
* Lacework-Control-Tower-CloudTrail-Log-Account-_Lacework account_
* Lacework-Control-Tower-Config-Member-_Lacework account_

Examining these stacksets for operation results, stack instance results and parameters may also provide debug information.

#### Lambda Function CloudWatch Logs

Two main Lambda functions are used to manage accounts. LaceworkSetupFunction manages the initial deployment of the integration. LaceworkAccountFunction manages setting up existing and new accounts. Both Lambda functions provide extensive debug messages that can be seen in their respective CloudWatch log streams.

## Reference Documentation
- [Support docs on docs.lacework.com](https://docs.lacework.com/aws-config-and-cloudtrail-integration-with-aws-control-tower-using-cloudformation#troubleshooting)
- [Implementation Guide on AWS](https://d1.awsstatic.com/Marketplace/solutions-center/downloads/AWSMP-CT-Implementation-Guide-Lacework-Multi-Account-Security.pdf)
- [Datasheet](https://d1.awsstatic.com/Marketplace/solutions-center/downloads/AWSMP-CT-Datasheet-Lacework-Multi-Account-SEC.pdf)
- [AWS Control Tower Getting Started](https://docs.aws.amazon.com/controltower/latest/userguide/getting-started-with-control-tower.html)