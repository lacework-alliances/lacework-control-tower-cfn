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


def message_processing(messages):
    logger.info("account.message_processing called.")
    target_stackset = {}
    for message in messages:
        payload = json.loads(message['Sns']['Message'])
        stackset_check(payload)


def stackset_check(messages):
    logger.info("account.stackset_check called.")
    cloud_formation_client = session.client("cloudformation")
    sqs_client = session.client("sqs")
    sns_client = session.client("sns")
    lacework_account_sns = os.environ['lacework_account_sns']
    lacework_dlq = os.environ['lacework_dlq']

    for stack_set_name, params in messages.items():
        logger.info("Checking stack set instances: {} {}".format(stack_set_name, params['OperationId']))
        try:
            stackset_status = cloud_formation_client.describe_stack_set_operation(
                StackSetName=stack_set_name,
                OperationId=params['OperationId']
            )
            if "StackSetOperation" in stackset_status:
                if stackset_status['StackSetOperation']['Status'] in ["RUNNING", "STOPPING", "QUEUED"]:
                    logger.info("Stack set operation still running")
                    message_body = {stack_set_name: {"OperationId": params['OperationId']}}
                    try:
                        logger.info("Sleep and wait for 20 seconds")
                        time.sleep(20)
                        sns_response = sns_client.publish(
                            TopicArn=lacework_account_sns,
                            Message=json.dumps(message_body))

                        logger.info("Re-queued for account creation: {}".format(sns_response))
                    except Exception as sns_exception:
                        logger.error("Failed to send queue for account creation: {}".format(sns_exception))

                elif stackset_status['StackSetOperation']['Status'] in ['SUCCEEDED']:
                    logger.info("Start account creation")
                    cloud_formation_paginator = cloud_formation_client.get_paginator("list_stack_set_operation_results")
                    stackset_iterator = cloud_formation_paginator.paginate(
                        StackSetName=stack_set_name,
                        OperationId=params['OperationId']
                    )

                    lacework_api_credentials = os.environ['lacework_api_credentials']
                    lacework_account_name = os.environ['lacework_account_name']
                    token = get_access_token(lacework_api_credentials)

                    if token:
                        for page in stackset_iterator:
                            if "Summaries" in page:
                                for operation in page['Summaries']:
                                    if operation['Status'] in ("SUCCEEDED"):
                                        target_account = operation['Account']
                                        logger.info("call the correct add account here")

                elif stackset_status['StackSetOperation']['Status'] in ['FAILED","STOPPED']:
                    logger.warning("Stackset operation failed/stopped")
                    message_body = {stack_set_name: {"OperationId": params['OperationId']}}
                    try:
                        sqs_response = sqs_client.send_message(
                            QueueUrl=lacework_dlq,
                            MessageBody=json.dumps(message_body))
                        logger.info("Sent to DLQ: {}".format(sqs_response))
                    except Exception as sqs_exception:
                        logger.error("Failed to send to DLQ: {}".format(sqs_exception))

        except Exception as e:
            logger.error(
                "Error processing stack set instance: {} {} Exception {}".format(stack_set_name, params['OperationId'],
                                                                                 e))


def get_access_token(lacework_api_credentials):
    logger.info("stackset.get_access_token called.")
    lacework_api_credentials = os.environ['lacework_api_credentials']

    secret_client = session.client('secretsmanager')
    try:
        secret_response = secret_client.get_secret_value(
            SecretId=lacework_api_credentials
        )
        if 'SecretString' not in secret_response:
            logger.error("SecretString not found in {}".format(lacework_api_credentials))
            return None

        secret_string_dict = json.loads(secret_response['SecretString'])
        access_token = secret_string_dict['AccessToken']

        return access_token

    except Exception as e:
        logger.error("Get access token error: {}.".format(e))
        return None


def lacework_add_cloud_account_for_cfg(aws_account_id, access_token, lacework_account_id, lacework_integration_list):
    logger.info("account.lacework_add_cloud_account_for_cfg")


def lacework_add_cloud_account_for_ct_cfg(aws_account_id, access_token, lacework_account_id, lacework_integration_list):
    logger.info("account.lacework_add_cloud_account_for_ct_cfg")
