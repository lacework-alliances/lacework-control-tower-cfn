# Lacework AWS Control Tower Customization

![Lacework](https://www.lacework.com/wp-content/uploads/2021/08/Lacework_Logo_RGB_01-1.svg)

## Overview
Lacework's AWS Control Tower Customization enables a seamless AWS account onboarding experience with the Lacework platform. Account administrators can automatically add Lacework's security auditing and monitoring to new AWS accounts during account creation. All the required Lacework and AWS account configuration that allows access to AWS configuration and CloudTrail logs are managed for you by this AWS Control Tower Customization.

## Architecture
![Architecture](https://drive.google.com/uc?export=view&id=1m-cLpc6ziv-9KB3FCbt3dyjPjEch9L6h)

### Setup Flow

1. The Administrator applies Lacework's main Control Tower Integration template in Cloudformation.
2. This template provisions all resources which includes a stack set, roles & permissions, Lambda functions, SNS & SQS topics/queues and EventBridge rule.
3. The Setup Lambda Function provisions any initial AWS accounts by sending an SNS message to the StackSet Lambda Function.
4. The StackSet Lambda Function creates a new Stack instance(s) for the account(s).
3. The Stack instance creates a new cross-account role, configures CloudTrail audit logs and security audit permissions for the account.
4. The StackSet Lambda Function sends an SNS notification to trigger the Account Lambda Function.
5. The Account Lambda Function creates a new account in Lacework for the new AWS account using a Lacework API key.
6. The Account Lambda Function sends an SNS notification to trigger the Auth Lambda Function to acquire a temporary access token from Lacework for subsequent accounts.


### New Account Flow

1. A new AWS account triggers a Control Tower lifecycle event which is picked up but by the EventBridge rule.
2. The EventBridge rule triggers the StackSet Lambda Function to create a new Stack instance for the account.
3. The Stack instance creates a new cross-account role, configures CloudTrail audit logs and security audit permissions for the account.
4. The StackSet Lambda Function sends an SNS notification to trigger the Account Lambda Function.
5. The Account Lambda Function creates a new account in Lacework for the new AWS account using a Lacework temporary access token.
6. If the Lacework access token is near expiration, the Account Lambda Function will send an SNS notification to trigger the Auth Lambda Function to refresh the temporary access token from Lacework.
