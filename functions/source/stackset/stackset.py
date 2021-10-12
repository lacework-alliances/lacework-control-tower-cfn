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
import boto3
import json
import logging
import os
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger("boto3").setLevel(logging.CRITICAL)
logging.getLogger("botocore").setLevel(logging.CRITICAL)
session = boto3.Session()


def lambda_handler(event, context):
    logger.info("stack_set.lambda_handler called.")
    logger.info(json.dumps(event))
    try:
        # called from stack_setSNS
        if 'Records' in event:
            stack_set_sns_processing(event['Records'])
        # called from event bridge rule
        elif 'detail' in event and event['detail']['eventName'] == 'CreateManagedAccount':
            lifecycle_eventbridge_processing(event)
        else:
            logger.info("Event not processed.")
    except Exception as e:
        logger.error(e)


def stack_set_sns_processing(messages):
    logger.info("stack_set.message_processing called.")
    target_stack_set = {}
    for message in messages:
        payload = json.loads(message['Sns']['Message'])
        cfn_stack_set_processing(payload)


def lifecycle_eventbridge_processing(event):
    logger.info("stack_set.lifecycle_processing called.")
    logger.info(json.dumps(event))
    if event['detail']['serviceEventDetails']['createManagedAccountStatus']['state'] == "SUCCEEDED":
        cloud_formation_client = session.client("cloudformation")
        account_id = event['detail']['serviceEventDetails']['createManagedAccountStatus']['account']['accountId']
        stack_set_name = os.environ['stack_set_name']
        stack_set_instances = list_stack_instance_by_account(session, stack_set_name, account_id)
        stack_set_instances_regions = list_stack_instance_region(session, stack_set_name)

        logger.info("Processing Lifecycle event for {}".format(account_id))
        # stack_set instance does not exist, create a new one
        if len(stack_set_instances) == 0:
            logger.info("Create new stack_set instance for {} {} {}".format(stack_set_name, account_id,
                                                                            stack_set_instances_regions))
            message_body = {stack_set_name: {"target_accounts": [account_id],
                                             "target_regions": stack_set_instances_regions}}
            cfn_stack_set_processing(message_body)

        # stack_set instance already exist, check for missing region
        elif len(stack_set_instances) > 0:
            stack_set_region = []
            for instance in stack_set_instances:
                stack_set_region.append(instance['Region'])
            next_region = list(set(stack_set_instances_regions) - set(stack_set_region))
            if len(next_region) > 0:
                logger.info(
                    "Append new stack_set instance for {} {} {}".format(stack_set_name, account_id, next_region))
                message_body = {stack_set_name: {"target_accounts": [account_id], "target_regions": next_region}}
                cfn_stack_set_processing(message_body)
            else:
                logger.info("stack_set instance already exist : {}".format(stack_set_instances))
    else:
        logger.error("Invalid event state, expected: SUCCEEDED : {}".format(event))


def cfn_stack_set_processing(messages):
    logger.info("stack_set.stack_set_processing called.")
    cloud_formation_client = session.client("cloudformation")
    sns_client = session.client("sns")
    lacework_stack_set_sns = os.environ['lacework_stack_set_sns']
    lacework_account_sns = os.environ['lacework_account_sns']
    lacework_auth_sns = os.environ['lacework_auth_sns']
    lacework_api_credentials = os.environ['lacework_api_credentials']

    for stack_set_name, params in messages.items():
        logger.info("Processing stack instances for {}".format(stack_set_name))
        param_accounts = params['target_accounts']
        param_regions = params['target_regions']
        logger.info("Target accounts : {}".format(param_accounts))
        logger.info("Target regions: {}".format(param_regions))

        try:
            stack_operations = True
            cloud_formation_client.describe_stack_set(StackSetName=stack_set_name)
            cloud_formation_paginator = cloud_formation_client.get_paginator("list_stack_set_operations")
            stack_set_iterator = cloud_formation_paginator.paginate(
                StackSetName=stack_set_name
            )
            for page in stack_set_iterator:
                if "Summaries" in page:
                    for operation in page['Summaries']:
                        if operation['Status'] in ("RUNNING", "STOPPING"):
                            stack_operations = False
                            break
                    if not stack_operations:
                        break

            if stack_operations:
                response = cloud_formation_client.create_stack_instances(StackSetName=stack_set_name,
                                                                         Accounts=param_accounts,
                                                                         Regions=param_regions)  # TODO need to override some parameter values in the stack set here
                logger.info("stack_set instance created {}".format(response))
                message_body = {stack_set_name: {"OperationId": response['OperationId']}}
                try:
                    sns_response = sns_client.publish(
                        TopicArn=lacework_account_sns,
                        Message=json.dumps(message_body))

                    logger.info("Queued for registration: {}".format(sns_response))
                except Exception as snsException:
                    logger.error("Failed to send queue for account creation: {}".format(snsException))
            else:
                logger.warning("Existing stack_set operations still running")
                message_body = {stack_set_name: messages[stack_set_name]}
                try:
                    logger.info("Sleep and wait for 20 seconds")
                    time.sleep(20)
                    sns_response = sns_client.publish(
                        TopicArn=lacework_stack_set_sns,
                        Message=json.dumps(message_body))

                    logger.info("Re-queued for stack_set instance creation: {}".format(sns_response))
                except Exception as snsException:
                    logger.error("Failed to send queue for stack_set instance creation: {}".format(snsException))

        except cloud_formation_client.exceptions.stack_setNotFoundException as describeException:
            logger.error("Exception getting stack set, {}".format(describeException))
            raise describeException


def list_stack_instance_by_account(target_session, stack_set_name, account_id):
    logger.info("stack_set.list_stack_instance_by_account called.")
    logger.info(target_session)
    try:
        cfn_client = target_session.client("cloudformation")
        stack_set_result = cfn_client.list_stack_instances(
            StackSetName=stack_set_name,
            StackInstanceAccount=account_id
        )

        logger.info("stack_set_result: {}".format(stack_set_result))
        if stack_set_result and "Summaries" in stack_set_result:
            stack_set_list = stack_set_result['Summaries']
            while "NextToken" in stack_set_result:
                stack_set_result = cfn_client.list_stack_set_instance(
                    NextToken=stack_set_result['NextToken']
                )
                stack_set_list.append(stack_set_result['Summaries'])

            return stack_set_list
        else:
            return False
    except Exception as e:
        logger.error("List Stack Instance error: {}.".format(e))
        return False


def list_stack_instance_region(target_session, stack_set_name):
    logger.info("stack_set.list_stack_instance_region called.")
    logger.info(target_session)
    try:
        cfn_client = target_session.client("cloudformation")
        stack_set_result = cfn_client.list_stack_instances(
            StackSetName=stack_set_name
        )
        logger.info("stack_set_result: {}".format(stack_set_result))
        if stack_set_result and "Summaries" in stack_set_result:
            stack_set_list = stack_set_result['Summaries']
            while "NextToken" in stack_set_result:
                stack_set_result = cfn_client.list_stack_set_instance(
                    NextToken=stack_set_result['NextToken']
                )
                stack_set_list.append(stack_set_result['Summaries'])

            stack_set_list_region = []
            for instance in stack_set_list:
                stack_set_list_region.append(instance['Region'])
            stack_set_list_region = list(set(stack_set_list_region))

            return stack_set_list_region
        else:
            return False
    except Exception as e:
        logger.error("List Stack Instance error: {}.".format(e))
        return False
