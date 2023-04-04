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
import random
import string

import boto3
import json
import logging
import os
import time

from aws import list_stack_instance_by_account_region, is_account_valid, wait_for_stack_set_operation, \
    get_org_for_account, create_stack_set_instances, stack_set_instance_exists, delete_stack_set_instances
from honeycomb import send_honeycomb_event
from lacework import get_account_from_url, get_access_token, add_lw_cloud_account_for_cfg, \
    lw_cloud_account_exists_in_orgs, delete_lw_cloud_account_in_orgs, update_lw_cloud_account_in_orgs, \
    setup_initial_access_token

HONEY_API_KEY = "$HONEY_KEY"
DATASET = "$DATASET"
BUILD_VERSION = "$BUILD"

CONFIG_NAME_PREFIX = "Lacework-Control-Tower-Config-Member-"

LOGLEVEL = os.environ.get('LOGLEVEL', logging.INFO)
logger = logging.getLogger()
logger.setLevel(LOGLEVEL)

HANDLED_EVENTS = {'CreateManagedAccount', 'UpdateManagedAccount'}


def lambda_handler(event, context):
    logger.info("account.lambda_handler called.")
    logger.info(json.dumps(event))
    try:
        # called from stack_setSNS
        if 'Records' in event:
            stack_set_sns_processing(event['Records'])
        # called from event bridge rule
        elif 'detail' in event and event['detail']['eventName'] in HANDLED_EVENTS:
            lifecycle_eventbridge_processing(event)
        else:
            logger.info("Event not processed.")
    except Exception as e:
        logger.error(e)


def stack_set_sns_processing(messages):
    logger.info("account.message_processing called.")
    for message in messages:
        payload = json.loads(message['Sns']['Message'])
        cfn_stack_set_processing(payload)


def lifecycle_eventbridge_processing(event):
    logger.info("account.lifecycle_eventbridge_processing called.")
    logger.info(json.dumps(event))
    if 'createManagedAccountStatus' in event['detail']['serviceEventDetails'] and \
            event['detail']['serviceEventDetails']['createManagedAccountStatus']['state'] == "SUCCEEDED":
        account_id = event['detail']['serviceEventDetails']['createManagedAccountStatus']['account']['accountId']
        logger.info("Processing createManagedAccountStatus event for account: {}".format(account_id))
        process_ct_lifecycle_event(account_id, event)
    elif 'updateManagedAccountStatus' in event['detail']['serviceEventDetails'] and \
            event['detail']['serviceEventDetails']['updateManagedAccountStatus']['state'] == "SUCCEEDED":
        account_id = event['detail']['serviceEventDetails']['updateManagedAccountStatus']['account']['accountId']
        logger.info("Processing updateManagedAccountStatus event for account: {}".format(account_id))
        process_ct_lifecycle_event(account_id, event)
    else:
        logger.error("Invalid event state, expected: SUCCEEDED : {}".format(event))


def process_ct_lifecycle_event(account_id, event):
    region = event['detail']['awsRegion']
    lacework_url = os.environ['lacework_url']
    lacework_account_name = get_account_from_url(lacework_url)
    lacework_sub_account_name = os.environ['lacework_sub_account_name']
    send_honeycomb_event(HONEY_API_KEY, DATASET, BUILD_VERSION, lacework_account_name, "add account",
                         lacework_sub_account_name)
    config_stack_set_name = CONFIG_NAME_PREFIX + \
                            (lacework_account_name if not lacework_sub_account_name else lacework_sub_account_name)
    logger.info("Processing Lifecycle event for {} in {}".format(account_id, region))
    message_body = {config_stack_set_name: {"target_accounts": [account_id],
                                            "target_regions": [region]}}
    cfn_stack_set_processing(message_body)


def cfn_stack_set_processing(messages):
    logger.info("account.stack_set_processing called.")
    cloud_formation_client = boto3.client("cloudformation")
    sns_client = boto3.client("sns")
    lacework_url = os.environ['lacework_url']
    lacework_account_name = get_account_from_url(lacework_url)
    lacework_sub_account_name = os.environ['lacework_sub_account_name']
    lacework_org_sub_account_names = os.environ['lacework_org_sub_account_names']
    lacework_account_sns = os.environ['lacework_account_sns']
    lacework_api_credentials = os.environ['lacework_api_credentials']
    setup_initial_access_token(lacework_url, lacework_api_credentials)
    access_token = get_access_token(lacework_api_credentials)

    if access_token is None:
        logger.error("Unable to get Lacework access token. Failed to create stack instances.")
        return None

    for config_stack_set_name, params in messages.items():
        logger.info("Processing stack instances for {}".format(config_stack_set_name))
        param_accounts = params['target_accounts']
        param_regions = params['target_regions']
        logger.info("Target accounts : {}".format(param_accounts))
        logger.info("Target regions: {}".format(param_regions))

        try:
            stack_operations = True
            cloud_formation_client.describe_stack_set(StackSetName=config_stack_set_name)
            cloud_formation_paginator = cloud_formation_client.get_paginator("list_stack_set_operations")
            stack_set_iterator = cloud_formation_paginator.paginate(
                StackSetName=config_stack_set_name
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
                valid_account_list = []
                for acct in param_accounts:
                    if is_account_valid(acct, lacework_org_sub_account_names):
                        logger.info("Adding valid acct {}".format(acct))
                        valid_account_list.append(acct)
                    elif lacework_org_sub_account_names and \
                            lw_cloud_account_exists_in_orgs(CONFIG_NAME_PREFIX + acct, lacework_url, access_token,
                                                            lacework_org_sub_account_names):
                        delete_lw_cloud_account_in_orgs(CONFIG_NAME_PREFIX + acct,
                                                        lacework_url, access_token, lacework_org_sub_account_names)
                        logger.info("Deleting acct {} from Lacework. Moved out of specified orgs.".format(acct))
                        delete_stack_set_instances(config_stack_set_name, [acct], param_regions)
                    else:
                        logger.info("Skipping acct {}".format(acct))

                if len(valid_account_list) == 0:
                    logger.warning("No valid accounts to add to Lacework: {}.".format(param_accounts))
                    return None

                # check if stack_set_instance_exists()
                create_stack_instance_list = []
                for acct in valid_account_list:
                    if not stack_set_instance_exists(config_stack_set_name, acct):
                        create_stack_instance_list.append(acct)

                external_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))
                if len(create_stack_instance_list) > 0:
                    response = create_stack_set_instances(config_stack_set_name, create_stack_instance_list,
                                                          param_regions, [
                                                              {
                                                                  "ParameterKey": "AccessToken",
                                                                  "ParameterValue": access_token,
                                                                  "UsePreviousValue": False,
                                                                  "ResolvedValue": "string"
                                                              },
                                                              {
                                                                  "ParameterKey": "ExternalID",
                                                                  "ParameterValue": external_id,
                                                                  "UsePreviousValue": False,
                                                                  "ResolvedValue": "string"
                                                              }
                                                          ])

                    wait_for_stack_set_operation(config_stack_set_name, response['OperationId'])
                    logger.info("Stack_set instance created {}".format(response))
                    time.sleep(10)

                for acct in valid_account_list:
                    org_name = get_org_for_account(acct, lacework_org_sub_account_names)
                    account_name = lacework_account_name if not lacework_sub_account_name else lacework_sub_account_name
                    sub_account_name = account_name if not org_name else org_name
                    role_arn = get_cross_account_access_role(lacework_account_name, account_name, acct)
                    if lacework_org_sub_account_names:
                        if lw_cloud_account_exists_in_orgs(CONFIG_NAME_PREFIX + acct, lacework_url, access_token,
                                                           lacework_org_sub_account_names):
                            update_lw_cloud_account_in_orgs(CONFIG_NAME_PREFIX + acct, lacework_url, sub_account_name,
                                                            access_token,
                                                            lacework_org_sub_account_names, role_arn, acct)
                        else:
                            add_lw_cloud_account_for_cfg(CONFIG_NAME_PREFIX + acct, lacework_url, sub_account_name,
                                                         access_token,
                                                         external_id,
                                                         role_arn, acct)
                    else:
                        add_lw_cloud_account_for_cfg(CONFIG_NAME_PREFIX + acct, lacework_url, sub_account_name,
                                                     access_token,
                                                     external_id,
                                                     role_arn, acct)
                    logger.info("Added acct {} to {} in Lacework".format(acct, account_name))
            else:
                logger.warning("Existing stack_set operations still running")
                message_body = {config_stack_set_name: messages[config_stack_set_name]}
                try:
                    logger.info("Sleep and wait for 20 seconds")
                    time.sleep(20)
                    sns_response = sns_client.publish(
                        TopicArn=lacework_account_sns,
                        Message=json.dumps(message_body))

                    logger.info("Re-queued for stack_set instance creation: {}".format(sns_response))
                except Exception as sns_exception:
                    logger.error("Failed to send queue for stack_set instance creation: {}".format(sns_exception))

        except Exception as describe_exception:
            logger.error("Exception getting stack set, {}".format(describe_exception))
            raise describe_exception


def get_cross_account_access_role(lacework_account_name, lacework_sub_account_name, acct_id):
    if not lacework_sub_account_name:
        return "arn:aws:iam::" + acct_id + ":role/" \
               + lacework_account_name + "-laceworkcwsrole-sa"
    else:
        return "arn:aws:iam::" + acct_id + ":role/" \
               + lacework_sub_account_name + "-laceworkcwsrole-sa"
