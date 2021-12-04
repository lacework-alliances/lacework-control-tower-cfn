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

import requests
import urllib3
from crhelper import CfnResource

SUCCESS = "SUCCESS"
FAILED = "FAILED"

LOG_NAME_PREFIX = "Lacework-Control-Tower-CloudTrail-Log-Account-"
AUDIT_NAME_PREFIX = "Lacework-Control-Tower-CloudTrail-Audit-Account-"
CONFIG_NAME_PREFIX = "Lacework-Control-Tower-Config-Member-"

STACK_SET_SUCCESS_STATES = ["SUCCEEDED"]
STACK_SET_RUNNING_STATES = ["RUNNING", "STOPPING"]

DESCRIPTION = "Lacework's cloud-native threat detection, compliance, behavioral anomaly detection, "
"and automated AWS security monitoring."

http = urllib3.PoolManager()

LOGLEVEL = os.environ.get('LOGLEVEL', logging.INFO)
logger = logging.getLogger()
logger.setLevel(LOGLEVEL)
logging.getLogger("boto3").setLevel(logging.CRITICAL)
logging.getLogger("botocore").setLevel(logging.CRITICAL)
session = boto3.Session()

helper = CfnResource(json_logging=False, log_level="INFO", boto_level="CRITICAL", sleep_on_delete=15)


def lambda_handler(event, context):
    logger.info("setup.lambda_handler called.")
    logger.info(json.dumps(event))
    try:
        if "RequestType" in event: helper(event, context)
    except Exception as e:
        helper.init_failure(e)


@helper.create
@helper.update
def create(event, context):
    logger.info("setup.create called.")
    logger.info(json.dumps(event))

    lacework_url = os.environ['lacework_url']
    lacework_account_name = get_account_from_url(lacework_url)
    lacework_sub_account_name = os.environ['lacework_sub_account_name']
    lacework_api_credentials = os.environ['lacework_api_credentials']
    send_honeycomb_event(lacework_account_name, "create started", lacework_sub_account_name)

    if not lacework_sub_account_name:
        logger.info("Sub account was not specified.")

    logger.info("Lacework URL: {}, Lacework account: {}, Lacework Sub Account: {}".format(lacework_url,
                                                                                          lacework_account_name,
                                                                                          lacework_sub_account_name))
    access_token = setup_initial_access_token(lacework_url, lacework_sub_account_name, lacework_api_credentials)
    if access_token is None:
        message = "Unable to get Lacework access token. Failed setup."
        logger.error(message)
        send_cfn_response(event, context, FAILED, {"Message": message})
        return None

    lacework_account_sns = os.environ['lacework_account_sns']
    capability_type = os.environ['capability_type']
    existing_accounts = os.environ['existing_accounts']
    log_account_name = os.environ['log_account_name']
    log_account_template = os.environ['log_account_template']
    audit_account_name = os.environ['audit_account_name']
    audit_account_template = os.environ['audit_account_template']
    member_account_template = os.environ['member_account_template']
    existing_cloudtrail = os.environ['existing_cloudtrail']

    management_account_id = context.invoked_function_arn.split(":")[4]
    region_name = context.invoked_function_arn.split(":")[3]
    external_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))

    try:
        if capability_type == "CloudTrail+Config":
            setup_cloudtrail(lacework_url, lacework_sub_account_name, region_name, management_account_id,
                             log_account_name,
                             log_account_template,
                             audit_account_name,
                             audit_account_template, access_token, external_id, existing_cloudtrail)

        setup_config(lacework_url, lacework_account_name, lacework_sub_account_name, lacework_account_sns,
                     existing_accounts,
                     member_account_template,
                     management_account_id,
                     region_name, access_token, external_id)

    except Exception as setup_exception:
        logger.error("Setup failed {}.".format(setup_exception))
        send_cfn_response(event, context, FAILED, {})
        return None

    send_honeycomb_event(lacework_account_name, "create completed", lacework_sub_account_name)
    send_cfn_response(event, context, SUCCESS, {})
    return None


@helper.delete  # crhelper method to delete stack set and stack instances
def delete(event, context):
    logger.info("setup.delete called.")
    lacework_url = os.environ['lacework_url']
    lacework_account_name = get_account_from_url(lacework_url)
    lacework_sub_account_name = os.environ['lacework_sub_account_name']
    log_account_name = os.environ['log_account_name']
    audit_account_name = os.environ['audit_account_name']
    region_name = context.invoked_function_arn.split(":")[3]
    lacework_api_credentials = os.environ['lacework_api_credentials']
    config_stack_set_name = CONFIG_NAME_PREFIX + \
                            (lacework_account_name if not lacework_sub_account_name else lacework_sub_account_name)

    send_honeycomb_event(lacework_account_name, "delete started", lacework_sub_account_name)

    cloudformation_client = session.client("cloudformation")

    try:
        paginator = cloudformation_client.get_paginator("list_stack_instances")
        page_iterator = paginator.paginate(StackSetName=config_stack_set_name)
        stack_set_list = []
        account_list = []
        region_list = []
        for page in page_iterator:
            if "Summaries" in page:
                stack_set_list.extend(page['Summaries'])
        for instance in stack_set_list:
            acct = instance['Account']
            region = instance['Region']
            try:
                if get_account_status_by_id(acct) == "ACTIVE":
                    account_list.append(acct)
                    region_list.append(region)
                    logger.info("Adding acct {}".format(acct))
                else:
                    logger.info("Skipping acct {}".format(acct))
            except Exception as account_status_exception:
                logger.warning("Account status exception for acct {} {}".format(acct,
                                                                                account_status_exception))

        region_list = list(set(region_list))
        account_list = list(set(account_list))
        logger.info("StackSet instances found in region(s): {}".format(region_list))
        logger.info("StackSet instances found in account(s): {}".format(account_list))

        if len(account_list) > 0:
            response = cloudformation_client.delete_stack_instances(
                StackSetName=config_stack_set_name,
                Accounts=account_list,
                Regions=region_list,
                RetainStacks=False)
            logger.info(response)

            wait_for_stack_set_operation(config_stack_set_name, response['OperationId'])

    except Exception as stack_instance_exception:
        logger.warning("Problem occurred while deleting, StackSet {} instances still exist : {}"
                       .format(config_stack_set_name, stack_instance_exception))

    try:
        response = cloudformation_client.delete_stack_set(StackSetName=config_stack_set_name)
        logger.info("StackSet {} template delete status {}".format(config_stack_set_name, response))
    except Exception as stack_set_exception:
        logger.warning("Problem occurred while deleting, StackSet {} still exist : {}".format(config_stack_set_name,
                                                                                              stack_set_exception))

    audit_stack_set_name = AUDIT_NAME_PREFIX + \
                           (lacework_account_name if not lacework_sub_account_name else lacework_sub_account_name)
    try:
        audit_account_id = get_account_id_by_name(audit_account_name)
        if audit_account_id is not None:
            audit_stack_instance_response = cloudformation_client.delete_stack_instances(
                StackSetName=audit_stack_set_name,
                Accounts=[audit_account_id],
                Regions=[region_name],
                RetainStacks=False)
            logger.info(audit_stack_instance_response)
            wait_for_stack_set_operation(audit_stack_set_name, audit_stack_instance_response['OperationId'])
        else:
            logger.warning("Audit account with name {} was not found.")

    except Exception as delete_audit_stack_exception:
        logger.warning(
            "Problem occurred while deleting, Lacework-CloudTrail-Audit-Account-Setup still exist : {}".format(
                delete_audit_stack_exception))

    try:
        audit_stack_set_response = cloudformation_client.delete_stack_set(StackSetName=audit_stack_set_name)
        logger.info("StackSet {} template delete status {}".format(audit_stack_set_name, audit_stack_set_response))
    except Exception as stack_set_exception:
        logger.warning("Problem occurred while deleting StackSet {} : {}".format(audit_stack_set_name,
                                                                                 stack_set_exception))
    log_stack_set_name = LOG_NAME_PREFIX + \
                         (lacework_account_name if not lacework_sub_account_name else lacework_sub_account_name)
    try:
        log_account_id = get_account_id_by_name(log_account_name)
        if log_account_id is not None:
            log_stack_instance_response = cloudformation_client.delete_stack_instances(
                StackSetName=log_stack_set_name,
                Accounts=[log_account_id],
                Regions=[region_name],
                RetainStacks=False)
            logger.info(log_stack_instance_response)
            wait_for_stack_set_operation(log_stack_set_name, log_stack_instance_response['OperationId'])
        else:
            logger.warning("Log account with name {} was not found.".format(log_account_id))

    except Exception as delete_log_stack_exception:
        logger.warning(
            "Problem occurred while deleting StackSet {} : {}".format(log_stack_set_name,
                                                                      delete_log_stack_exception))

    try:
        log_stack_set_response = cloudformation_client.delete_stack_set(StackSetName=log_stack_set_name)
        logger.info("StackSet {} template delete status {}".format(log_stack_set_name, log_stack_set_response))
    except Exception as stack_set_exception:
        logger.warning("Problem occurred while deleting, StackSet {} still exist : {}".format(log_stack_set_name,
                                                                                              stack_set_exception))

    try:
        access_token = get_access_token(lacework_api_credentials)
        if access_token is None:
            logger.warning("Unable to get Lacework access token. Failed to delete cloud account {}.")
        else:
            if not delete_lw_cloud_account_for_ct(log_stack_set_name, lacework_url, lacework_sub_account_name,
                                                  access_token):
                logger.warning("Failed to delete CloudTrail cloud account for {}.".format(lacework_account_name))
    except Exception as delete_exception:
        logger.warning("Failed to delete CloudTrail cloud account for {} {}.", lacework_account_name, delete_exception)

    send_honeycomb_event(lacework_account_name, "delete completed", lacework_sub_account_name)
    send_cfn_response(event, context, SUCCESS, {})
    return None


def send_cfn_response(event, context, response_status, response_data, physical_resource_id=None, no_echo=False,
                      reason=None):
    response_url = event['ResponseURL']

    logger.info(response_url)

    response_body = {
        'Status': response_status,
        'Reason': reason or "See the details in CloudWatch Log Stream: {}".format(context.log_stream_name),
        'PhysicalResourceId': physical_resource_id or context.log_stream_name,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'NoEcho': no_echo,
        'Data': response_data
    }

    json_response_body = json.dumps(response_body)

    logger.info("Response body: {}".format(json_response_body))

    headers = {
        'content-type': '',
        'content-length': str(len(json_response_body))
    }

    try:
        response = http.request('PUT', response_url, headers=headers, body=json_response_body)
        logger.info("Status code: {}".format(response.status))

    except Exception as e:
        logger.error("send_cfn_response error {}".format(e))


def setup_initial_access_token(lacework_url, lacework_sub_account_name, lacework_api_credentials):
    logger.info("setup.setup_initial_access_token called.")
    secret_client = session.client('secretsmanager')
    try:
        secret_response = secret_client.get_secret_value(
            SecretId=lacework_api_credentials
        )
        if 'SecretString' not in secret_response:
            logger.error("SecretString not found in {}".format(lacework_api_credentials))
            return None

        secret_string_dict = json.loads(secret_response['SecretString'])
        access_key_id = secret_string_dict['AccessKeyID']
        secret_key = secret_string_dict['SecretKey']

        access_token_response = send_lacework_api_access_token_request(lacework_url, access_key_id, secret_key)
        logger.info('API response code : {}'.format(access_token_response.status_code))
        logger.debug('API response : {}'.format(access_token_response.text))
        if access_token_response.status_code == 201:
            payload_response = access_token_response.json()
            expires_at = payload_response['expiresAt']
            token = payload_response['token']
            secret_string_dict['AccessToken'] = token
            secret_string_dict['TokenExpiry'] = expires_at
            secret_client.update_secret(SecretId=lacework_api_credentials, SecretString=json.dumps(secret_string_dict))
            logger.info("New access token saved to secrets manager.")
            return token
        else:
            logger.error("Generate access key failure {} {}".format(access_token_response.status_code,
                                                                    access_token_response.text))
            return None
    except Exception as e:
        logger.error("Error setting up initial access token {}".format(e))
        return None


def get_access_token(lacework_api_credentials):
    logger.info("setup.get_access_token called.")

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


def add_lw_cloud_account_for_ct(integration_name, lacework_url, lacework_sub_account_name, access_token,
                                external_id,
                                role_arn, sqs_queue_url):
    logger.info("setup.add_lw_cloud_account_for_ct")

    try:
        request_payload = '''
        {{
            "name": "{}", 
            "type": "AwsCtSqs",
            "enabled": 1,
            "data": {{
                "crossAccountCredentials": {{
                    "externalId": "{}",
                    "roleArn": "{}"
                }},
                "queueUrl": "{}"
            }}
        }}
        '''.format(integration_name, external_id, role_arn, sqs_queue_url)
        logger.info('Generate create account payload : {}'.format(request_payload))

        add_response = send_lacework_api_post_request(lacework_url, "api/v2/CloudAccounts", access_token,
                                                      request_payload, lacework_sub_account_name)
        logger.info('API response code : {}'.format(add_response.status_code))
        logger.info('API response : {}'.format(add_response.text))
        if add_response.status_code == 201:
            return True
        else:
            return False
    except Exception as e:
        logger.error("Error adding CloudTrail account {}".format(e))
        return False


def delete_lw_cloud_account_for_ct(integration_name, lacework_url, lacework_sub_account_name, access_token):
    logger.info("setup.delete_lw_cloud_account_for_ct")

    try:
        search_request_payload = '''
        {{
            "filters": [
                {{
                    "field": "name",
                    "expression": "eq",
                    "value": "{}"
                }}
            ],
            "returns": [
                "intgGuid"
            ]
        }}
        '''.format(integration_name)
        logger.info('Generate search account payload : {}'.format(search_request_payload))

        search_response = send_lacework_api_post_request(lacework_url, "api/v2/CloudAccounts/search", access_token,
                                                         search_request_payload, lacework_sub_account_name)
        logger.info('API response code : {}'.format(search_response.status_code))
        logger.info('API response : {}'.format(search_response.text))
        if search_response.status_code == 200:
            search_response_dict = json.loads(search_response.text)
            data_dict = search_response_dict['data'];
            if len(data_dict) == 0:
                logger.warning("Cloud account with integration name {} was not found.".format(integration_name))
                return False
            elif len(data_dict) > 1:
                logger.warning(
                    "More than one cloud account with integration name {} was found.".format(integration_name))
                return False
            intg_guid = data_dict[0]['intgGuid']

            delete_response = send_lacework_api_delete_request(lacework_url, "api/v2/CloudAccounts/"
                                                               + intg_guid, access_token, lacework_sub_account_name)
            logger.info('API response code : {}'.format(delete_response.status_code))
            logger.info('API response : {}'.format(delete_response.text))
            if delete_response.status_code == 204:
                return True
            else:
                return False
        else:
            return False
    except Exception as e:
        logger.error("Error deleting Cloud Account {} {}".format(integration_name, e))
        return False


def setup_cloudtrail(lacework_url, lacework_sub_account_name, region_name, management_account_id, log_account_name,
                     log_account_template, audit_account_name, audit_account_template, access_token, external_id,
                     existing_cloudtrail):
    logger.info("setup.setup_cloudtrail called.")

    log_account_id = get_account_id_by_name(log_account_name)
    if log_account_id is None:
        logger.error("Log account with name {} was not found.")
        raise Exception
    else:
        logger.info("Log account {} has AWS ID {}.".format(log_account_name, log_account_id))

    audit_account_id = get_account_id_by_name(audit_account_name)
    if audit_account_id is None:
        logger.error("Audit account with name {} was not found.")
        raise Exception
    else:
        logger.info("Audit account {} has AWS ID {}.".format(audit_account_name, audit_account_id))

    try:
        cloudtrail_client = boto3.client('cloudtrail')
        trail = cloudtrail_client.get_trail(
            Name=existing_cloudtrail
        )
        cloudtrail_s3_bucket = trail['Trail']['S3BucketName']
        cloudtrail_sns_topic = trail['Trail']['SnsTopicARN']
    except Exception as trail_exception:
        logger.error("Error getting cloudtrail {} {}.".format(existing_cloudtrail, trail_exception))
        raise trail_exception

    cloudformation_client = session.client("cloudformation")

    try:
        lacework_account_name = get_account_from_url(lacework_url)
        log_stack_set_name = LOG_NAME_PREFIX + \
                             (lacework_account_name if not lacework_sub_account_name else lacework_sub_account_name)
        cloudformation_client.describe_stack_set(StackSetName=log_stack_set_name)
        logger.info("Stack set {} already exist".format(log_stack_set_name))
    except Exception as describe_exception:
        logger.info("Stack set {} does not exist, creating it now. {}".format(log_stack_set_name, describe_exception))
        try:
            sqs_queue_url = get_sqs_queue_url(lacework_account_name, lacework_sub_account_name, region_name,
                                              audit_account_id)
            sqs_queue_arn = get_sqs_queue_arn(lacework_account_name, lacework_sub_account_name, region_name,
                                              audit_account_id)
            logger.info("SQS queue url is {}".format(sqs_queue_url))
            log_role = "arn:aws:iam::" + management_account_id + ":role/service-role/AWSControlTowerStackSetRole"
            logger.info("Creating log stack {} with ResourceNamePrefix: {} ExternalID: {} "
                        "ExistingTrailBucketName: {} SqsQueueUrl: {} SqsQueueArn: {}".format(log_account_template,
                                                                                             lacework_account_name,
                                                                                             external_id,
                                                                                             cloudtrail_s3_bucket,
                                                                                             sqs_queue_url,
                                                                                             sqs_queue_arn))
            cloudformation_client.create_stack_set(
                StackSetName=log_stack_set_name,
                Description=DESCRIPTION,
                TemplateURL=log_account_template,
                Parameters=[
                    {
                        "ParameterKey": "ResourceNamePrefix",
                        "ParameterValue": lacework_account_name if not lacework_sub_account_name else lacework_sub_account_name,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string"
                    },
                    {
                        "ParameterKey": "ExternalID",
                        "ParameterValue": external_id,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string"
                    },
                    {
                        "ParameterKey": "AccessToken",
                        "ParameterValue": access_token,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string"
                    },
                    {
                        "ParameterKey": "ExistingTrailBucketName",
                        "ParameterValue": cloudtrail_s3_bucket,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string"
                    },
                    {
                        "ParameterKey": "SqsQueueUrl",
                        "ParameterValue": sqs_queue_url,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string"
                    },
                    {
                        "ParameterKey": "SqsQueueArn",
                        "ParameterValue": sqs_queue_arn,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string"
                    }
                ],
                Capabilities=[
                    "CAPABILITY_NAMED_IAM"
                ],
                AdministrationRoleARN=log_role,
                ExecutionRoleName="AWSControlTowerExecution")

            try:
                cloudformation_client.describe_stack_set(StackSetName=log_stack_set_name)
                logger.info("StackSet {} deployed".format(log_stack_set_name))
            except cloudformation_client.exceptions.StackSetNotFoundException as describe_exception:
                message = "Exception getting new stack set, {}".format(describe_exception)
                logger.error(message)
                raise describe_exception

            log_stack_instance_response = cloudformation_client.create_stack_instances(
                StackSetName=log_stack_set_name,
                Accounts=[log_account_id],
                Regions=[region_name])

            wait_for_stack_set_operation(log_stack_set_name, log_stack_instance_response['OperationId'])

            logger.info("Log stack set instance created {}".format(log_stack_instance_response))
        except Exception as create_exception:
            logger.error("Error creating log account stack {}.".format(create_exception))
            raise create_exception

    try:
        audit_stack_set_name = AUDIT_NAME_PREFIX + \
                               (lacework_account_name if not lacework_sub_account_name else lacework_sub_account_name)
        cloudformation_client.describe_stack_set(StackSetName=audit_stack_set_name)
        logger.info("Stack set {} already exist".format(audit_stack_set_name))
    except Exception as describe_exception:
        logger.info("Stack set {} does not exist, creating it now. {}".format(audit_stack_set_name, describe_exception))
        try:
            logger.info("Existing trail: s3: {} topic: {}".format(cloudtrail_s3_bucket, cloudtrail_sns_topic))
            audit_role = "arn:aws:iam::" + management_account_id + ":role/service-role/AWSControlTowerStackSetRole"
            logger.info("Using role {} to create stack set url {}".format(audit_role, audit_account_template))
            cross_account_access_role = get_cross_account_access_role(lacework_account_name, lacework_sub_account_name,
                                                                      log_account_id)
            logger.info("Creating audit stack {} with ResourceNamePrefix: {} ExistingTrailTopicArn: {} "
                        "CrossAccountAccessRoleArn: {}".format(audit_account_template, lacework_account_name,
                                                               cloudtrail_sns_topic, cross_account_access_role))
            cloudformation_client.create_stack_set(
                StackSetName=audit_stack_set_name,
                Description=DESCRIPTION,
                TemplateURL=audit_account_template,
                Parameters=[
                    {
                        "ParameterKey": "ResourceNamePrefix",
                        "ParameterValue": lacework_account_name if not lacework_sub_account_name else lacework_sub_account_name,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string"
                    },
                    {
                        "ParameterKey": "ExistingTrailTopicArn",
                        "ParameterValue": cloudtrail_sns_topic,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string"
                    },
                    {
                        "ParameterKey": "CrossAccountAccessRoleArn",
                        "ParameterValue": cross_account_access_role,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string"
                    }
                ],
                Capabilities=[
                    "CAPABILITY_NAMED_IAM"
                ],
                AdministrationRoleARN=audit_role,
                ExecutionRoleName="AWSControlTowerExecution")

            try:
                cloudformation_client.describe_stack_set(StackSetName=audit_stack_set_name)
                logger.info("StackSet {} deployed".format(audit_stack_set_name))
            except cloudformation_client.exceptions.StackSetNotFoundException as describe_exception:
                message = "Exception getting new stack set, {}".format(describe_exception)
                logger.error(message)
                raise describe_exception

            audit_stack_instance_response = cloudformation_client.create_stack_instances(
                StackSetName=audit_stack_set_name,
                Accounts=[audit_account_id],
                Regions=[region_name])

            wait_for_stack_set_operation(audit_stack_set_name, audit_stack_instance_response['OperationId'])

            logger.info("Audit stack set instance created {}".format(audit_stack_instance_response))
        except Exception as create_exception:
            logger.error("Error creating audit account stack {}.".format(create_exception))
            raise create_exception

        try:
            result = add_lw_cloud_account_for_ct(log_stack_set_name, lacework_url, lacework_sub_account_name,
                                                 access_token, external_id,
                                                 cross_account_access_role,
                                                 sqs_queue_url)
            if not result:
                message = "Failed to create account in Lacework!"
                logger.error(message)
                raise Exception(message)

        except Exception as create_account_exception:
            logger.error("Error creating account in Lacework {}.".format(create_account_exception))
            raise create_account_exception


def setup_config(lacework_url, lacework_account_name, lacework_sub_account_name, lacework_account_sns,
                 existing_accounts,
                 member_account_template,
                 management_account_id, region_name, access_token, external_id):
    logger.info("setup.setup_config called.")
    cloudformation_client = session.client("cloudformation")
    try:
        config_stack_set_name = CONFIG_NAME_PREFIX + \
                                (lacework_account_name if not lacework_sub_account_name else lacework_sub_account_name)
        account_name = lacework_account_name if not lacework_sub_account_name else lacework_sub_account_name
        service_token = get_service_token(lacework_url, region_name)
        cloudformation_client.describe_stack_set(StackSetName=config_stack_set_name)
        logger.info("Stack set {} already exist".format(config_stack_set_name))
    except Exception as describe_exception:
        logger.info(
            "Stack set {} does not exist, creating it now. {}".format(config_stack_set_name, describe_exception))
        management_role = "arn:aws:iam::" + management_account_id + ":role/service-role/AWSControlTowerStackSetRole"
        logger.info("Using role {} to create stack {}".format(management_role, config_stack_set_name))
        logger.info("Creating config stack with ResourceNamePrefix: {} ExternalID: {} ".format(account_name,
                                                                                               external_id))
        cloudformation_client.create_stack_set(
            StackSetName=config_stack_set_name,
            Description="Lacework's cloud-native threat detection, compliance, behavioral anomaly detection, "
                        "and automated AWS security monitoring.",
            TemplateURL=member_account_template,
            Parameters=[
                {
                    "ParameterKey": "ResourceNamePrefix",
                    "ParameterValue": account_name,
                    "UsePreviousValue": False,
                    "ResolvedValue": "string"
                },
                {
                    "ParameterKey": "ExternalID",
                    "ParameterValue": external_id,
                    "UsePreviousValue": False,
                    "ResolvedValue": "string"
                },
                {
                    "ParameterKey": "AccessToken",
                    "ParameterValue": access_token,
                    "UsePreviousValue": False,
                    "ResolvedValue": "string"
                },
                {
                    "ParameterKey": "ServiceToken",
                    "ParameterValue": service_token,
                    "UsePreviousValue": False,
                    "ResolvedValue": "string"
                }
            ],
            Capabilities=[
                "CAPABILITY_NAMED_IAM"
            ],
            AdministrationRoleARN=management_role,
            ExecutionRoleName="AWSControlTowerExecution")

        try:
            cloudformation_client.describe_stack_set(StackSetName=config_stack_set_name)
            logger.info("StackSet {} deployed".format(config_stack_set_name))
        except cloudformation_client.exceptions.StackSetNotFoundException as describe_exception:
            message = "Exception getting new stack set, {}".format(describe_exception)
            logger.error(message)
            raise describe_exception

        if existing_accounts == "Yes":
            logger.info("Chose to deploy to existing accounts.")
            try:
                account_list = []

                paginator = cloudformation_client.get_paginator('list_stack_instances')
                page_iterator = paginator.paginate(StackSetName="AWSControlTowerBP-BASELINE-CLOUDTRAIL")
                for page in page_iterator:
                    for inst in page['Summaries']:
                        acct = inst['Account']
                        try:
                            status = get_account_status_by_id(acct)
                            logger.info("Acct {} is {}.".format(acct, status))
                            if status == "ACTIVE":
                                account_list.append(inst['Account'])
                                logger.info("Adding acct {}".format(acct))
                            else:
                                logger.info("Skipping acct {}".format(acct))
                        except Exception as account_status_exception:
                            logger.warning("Account status exception for acct {} {}".format(acct,
                                                                                            account_status_exception))

                logger.info("Accounts to deploy {}.".format(account_list))
                if len(account_list) > 0:
                    logger.info("New accounts : {}".format(account_list))
                    send_honeycomb_event(lacework_account_name, "add {} existing".format(len(account_list)),
                                         lacework_sub_account_name)
                    sns_client = session.client("sns")
                    message_body = {
                        config_stack_set_name: {"target_accounts": account_list, "target_regions": [region_name]}}
                    try:
                        sns_response = sns_client.publish(
                            TopicArn=lacework_account_sns,
                            Message=json.dumps(message_body))

                        logger.info("Queued for stackset instance creation: {}".format(sns_response))
                    except Exception as sns_exception:
                        logger.error("Failed to send queue for stackset instance creation: {}".format(sns_exception))
                else:
                    logger.info("No additional stackset instances requested")
            except Exception as create_exception:
                message = "Exception creating stack instance with {}".format(create_exception)
                logger.error(message)
                raise create_exception
        else:
            logger.info("Chose NOT to deploy to existing accounts.")


def get_account_id_by_name(name):
    logger.info("setup.get_account_id_by_name called.")
    org_client = session.client('organizations')
    paginator = org_client.get_paginator("list_accounts")
    page_iterator = paginator.paginate()
    for page in page_iterator:
        for acct in page['Accounts']:
            if acct['Name'] == name:
                return acct['Id']

    return None


def get_account_status_by_id(id):
    logger.info("setup.get_account_status_by_id called.")
    org_client = session.client('organizations')
    try:
        response = org_client.describe_account(
            AccountId=id
        )
        return response['Account']['Status']
    except Exception as describe_exception:
        logger.error("Exception getting account status on {} {}.".format(id, describe_exception))
        return "UNKNOWN"

    return None


def wait_for_stack_set_operation(stack_set_name, operation_id):
    logger.info("Waiting for StackSet Operation {} on StackSet {} to finish".format(operation_id, stack_set_name))
    cloudformation_client = session.client("cloudformation")
    finished = False
    status = ""
    while not finished:
        time.sleep(15)
        status = \
            cloudformation_client.describe_stack_set_operation(StackSetName=stack_set_name, OperationId=operation_id)[
                "StackSetOperation"
            ]["Status"]
        if status in STACK_SET_RUNNING_STATES:
            logger.info("{} {} still running.".format(stack_set_name, operation_id))
        else:
            finished = True

    logger.info("StackSet Operation finished with Status: {}".format(status))
    if status not in STACK_SET_SUCCESS_STATES:
        return False
    else:
        return True


def get_account_from_url(lacework_url):
    return lacework_url.split('.')[0]


def get_service_token(lacework_url, region_name):
    if ".fra." in lacework_url:
        return "arn:aws:sns:" + region_name + ":434813966438:euprodn-customer-cloudformation"
    else:
        return "arn:aws:sns:" + region_name + ":434813966438:prodn-customer-cloudformation"


def get_sqs_queue_arn(lacework_account_name, lacework_sub_account_name, region_name, audit_account_id):
    if not lacework_sub_account_name:
        return "arn:aws:sqs:" + region_name + ":" + audit_account_id + ":" \
               + lacework_account_name + "-laceworkcws"
    else:
        return "arn:aws:sqs:" + region_name + ":" + audit_account_id + ":" \
               + lacework_sub_account_name + "-laceworkcws"


def get_sqs_queue_url(lacework_account_name, lacework_sub_account_name, region_name, audit_account_id):
    if not lacework_sub_account_name:
        return "https://sqs." + region_name + ".amazonaws.com/" + audit_account_id + "/" \
               + lacework_account_name + "-laceworkcws"
    else:
        return "https://sqs." + region_name + ".amazonaws.com/" + audit_account_id + "/" \
               + lacework_sub_account_name + "-laceworkcws"


def get_cross_account_access_role(lacework_account_name, lacework_sub_account_name, log_account_id):
    if not lacework_sub_account_name:
        return "arn:aws:iam::" + log_account_id + ":role/" \
               + lacework_account_name + "-laceworkcwssarole"
    else:
        return "arn:aws:iam::" + log_account_id + ":role/" \
               + lacework_sub_account_name + "-laceworkcwssarole"


def get_log_stack_name(lacework_account_name, lacework_sub_account_name):
    if not lacework_sub_account_name:
        return LOG_NAME_PREFIX + lacework_account_name
    else:
        return LOG_NAME_PREFIX + lacework_sub_account_name


def get_audit_stack_name(lacework_account_name, lacework_sub_account_name):
    if not lacework_sub_account_name:
        return AUDIT_NAME_PREFIX + lacework_account_name
    else:
        return AUDIT_NAME_PREFIX + lacework_sub_account_name


def send_lacework_api_access_token_request(lacework_url, access_key_id, secret_key):
    request_payload = '''
        {{
            "keyId": "{}", 
            "expiryTime": 86400
        }}
        '''.format(access_key_id)
    logger.debug('Generate access key payload : {}'.format(json.dumps(request_payload)))
    try:
        return requests.post("https://" + lacework_url + "/api/v2/access/tokens",
                             headers={'X-LW-UAKS': secret_key, 'content-type': 'application/json'},
                             verify=True, data=request_payload)
    except Exception as api_request_exception:
        raise api_request_exception
        return None


def send_lacework_api_post_request(lacework_url, api, access_token, request_payload, sub_account_name):
    try:
        if not sub_account_name:
            return requests.post("https://" + lacework_url + "/" + api,
                                 headers={'Authorization': access_token, 'content-type': 'application/json'},
                                 verify=True, data=request_payload)
        else:
            return requests.post("https://" + lacework_url + "/" + api,
                                 headers={'Authorization': access_token, 'content-type': 'application/json',
                                          'Account-Name': sub_account_name},
                                 verify=True, data=request_payload)
    except Exception as api_request_exception:
        raise api_request_exception
        return None


def send_lacework_api_delete_request(lacework_url, api, access_token, sub_account_name):
    try:
        if not sub_account_name:
            return requests.delete("https://" + lacework_url + "/" + api,
                                   headers={'Authorization': access_token},
                                   verify=True)
        else:
            return requests.delete("https://" + lacework_url + "/" + api,
                                   headers={'Authorization': access_token,
                                            'Account-Name': sub_account_name},
                                   verify=True)
    except Exception as api_request_exception:
        raise api_request_exception
        return None


def send_honeycomb_event(account, event, subaccount="000000", eventdata="{}"):
    logger.info("setup.send_honeycomb_event called.")

    try:
        payload = '''
        {{
            "account": "{}",
            "sub-account": "{}",
            "tech-partner": "AWS",
            "integration-name": "lacework-aws-control-tower-cloudformation",
            "version": "master-0-g89c4d8a",
            "service": "AWS Control Tower",
            "install-method": "cloudformation",
            "function": "setup.py",
            "event": "{}",
            "event-data": {}
        }}
        '''.format(account, subaccount, event, eventdata)
        logger.info('Generate payload : {}'.format(payload))
        resp = requests.post("https://api.honeycomb.io/1/events/lacework-alliances-prod",
                             headers={'X-Honeycomb-Team': '',
                                      'content-type': 'application/json'},
                             verify=True, data=payload)
        logger.info ("Honeycomb response {} {}".format(resp, resp.content))

    except Exception as e:
        logger.warning("Get error sending to Honeycomb: {}.".format(e))
