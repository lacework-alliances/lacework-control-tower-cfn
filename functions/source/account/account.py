#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
import boto3, json, time, os, logging, botocore, requests
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger("boto3").setLevel(logging.CRITICAL)
logging.getLogger("botocore").setLevel(logging.CRITICAL)
session = boto3.Session()

def message_processing(messages):
    logger.info("account.message_processing called.")
    target_stackset = {}
    for message in messages:
        payload = json.loads(message['Sns']['Message'])
        stackset_check(payload)

def stackset_check(messages):
    logger.info("account.stackset_check called.")
    cloudFormationClient = session.client("cloudformation")
    sqsClient = session.client("sqs")
    snsClient = session.client("sns")
    laceworkAccountSNS = os.environ['laceworkAccountSNS']
    laceworkDLQ = os.environ['laceworkDLQ']
    
    for stackSetName, params in messages.items():
        logger.info("Checking stack set instances: {} {}".format(stackSetName, params['OperationId']))
        try:
            stackset_status = cloudFormationClient.describe_stack_set_operation(
                StackSetName=stackSetName,
                OperationId=params['OperationId']
            )
            if "StackSetOperation" in stackset_status:
                if stackset_status['StackSetOperation']['Status'] in ['RUNNING","STOPPING","QUEUED",]:
                    logger.info("Stackset operation still running")
                    messageBody = {}
                    messageBody[stackSetName] = {"OperationId": params['OperationId']}
                    try:
                        logger.info("Sleep and wait for 20 seconds")
                        time.sleep(20)
                        snsResponse = snsClient.publish(
                            TopicArn=laceworkAccountSNS,
                            Message = json.dumps(messageBody))

                        logger.info("Re-queued for account creation: {}".format(snsResponse))
                    except Exception as snsException:
                        logger.error("Failed to send queue for account creation: {}".format(snsException))
                
                elif stackset_status['StackSetOperation']['Status'] in ['SUCCEEDED']:
                    logger.info("Start account creation")
                    cloudFormationPaginator = cloudFormationClient.get_paginator("list_stack_set_operation_results")
                    stackset_iterator = cloudFormationPaginator.paginate(
                        StackSetName=stackSetName,
                        OperationId=params['OperationId']
                    )
                    
                    laceworkApiCredentials = os.environ['laceworkApiCredentials']
                    laceworkAccName = os.environ['laceworkAcctName']
                    laceworkAccessToken = get_access_token(laceworkApiCredentials)
                    
                    if laceworkAccessKey:
                        for page in stackset_iterator:
                            if "Summaries" in page:
                                for operation in page['Summaries']:
                                    if operation['Status'] in ("SUCCEEDED"):
                                        targetAccount = operation['Account']
                                        logger.info("call the correct add account here")
                    
                elif stackset_status['StackSetOperation']['Status'] in ['FAILED","STOPPED']:
                    logger.warning("Stackset operation failed/stopped")
                    messageBody = {}
                    messageBody[stackSetName] = {"OperationId": params['OperationId']}
                    try:
                        sqsResponse = sqsClient.send_message(
                            QueueUrl=laceworkDLQ,
                            MessageBody=json.dumps(messageBody))
                        logger.info("Sent to DLQ: {}".format(sqsResponse))
                    except Exception as sqsException:
                        logger.error("Failed to send to DLQ: {}".format(sqsException))
        
        except Exception as e:
            logger.error(e)

def get_access_token(secret_arn):
    logger.info("account.get_access_token called.")
    secretClient = session.client("secretsmanager")
    try:
        secret_response = secretClient.get_secret_value(
            SecretId=secret_arn
        )
        if "SecretString" in secret_response:
            token = json.loads(secret_response['SecretString'])['AccessToken']
            expiry = json.loads(secret_response['SecretString'])['TokenExpiry']
            if expiry - time.time() < 3600 :
                keyId = json.loads(secret_response['SecretString'])['AccessKeyId']
                messageBody = {}
                messageBody[keyId] = {"Refresh request"}
                try:
                    snsResponse = snsClient.publish(
                        TopicArn=laceworkAuthSNS,
                        Message = json.dumps(messageBody))

                    logger.info("Queued for token refresh: {}".format(snsResponse))
                except Exception as snsException:
                    logger.error("Failed to send queue for token refresh: {}".format(snsException))
            return token
    
    except Exception as e:
        logger.error("Get Secret Failed: " + str(e))
    
def lacework_add_cloud_account_for_cfg(aws_account_id, access_key, lacework_account_id, lacework_integration_list):
    logger.info("account.lacework_add_cloud_account_for_cfg")

def lacework_add_cloud_account_for_ct_cfg(aws_account_id, access_key, lacework_account_id, lacework_integration_list):
    logger.info("account.lacework_add_cloud_account_for_ct_cfg")


def lambda_handler(event, context):
    logger.info("account.lambda_handler called.")
    logger.info(json.dumps(event))
    try:
        if "Records" in event:
            message_processing(event['Records'])
        else:
            logger.error("Event not processed.")
    except Exception as e:
        logger.error(e)