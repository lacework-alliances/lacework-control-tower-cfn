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

    lacework_account_name = os.environ['lacework_account_name']
    lacework_api_credentials = os.environ['lacework_api_credentials']

    access_token = setup_initial_access_token(lacework_account_name, lacework_api_credentials)
    if access_token is None:
        message = "Unable to get Lacework access token. Failed setup."
        logger.error(message)
        send_cfn_response(event, context, FAILED, {"Message": message})
        return None

    stack_set_name = os.environ['stack_set_name']
    lacework_account_sns = os.environ['lacework_account_sns']
    capability_type = os.environ['capability_type']
    existing_accounts = os.environ['existing_accounts']
    log_account_name = os.environ['log_account_name']
    log_account_template = os.environ['log_account_template']
    audit_account_name = os.environ['audit_account_name']
    audit_account_template = os.environ['audit_account_template']
    member_account_template = os.environ['member_account_template']

    management_account_id = context.invoked_function_arn.split(":")[4]
    region_name = context.invoked_function_arn.split(":")[3]
    external_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))

    try:
        if capability_type == "CloudTrail+Config":
            setup_cloudtrail(lacework_account_name, region_name, management_account_id, log_account_name,
                             log_account_template,
                             audit_account_name,
                             audit_account_template, access_token, external_id)

        setup_config(stack_set_name, lacework_account_name, lacework_account_sns, existing_accounts,
                     member_account_template,
                     management_account_id,
                     region_name, access_token, external_id)
    except Exception as setup_exception:
        logger.error("Setup failed {}.".format(setup_exception))
        send_cfn_response(event, context, FAILED, {})
        return None

    send_cfn_response(event, context, SUCCESS, {})
    return None


@helper.delete  # crhelper method to delete stack set and stack instances
def delete(event, context):
    logger.info("setup.delete called.")
    delete_wait_time = (int(context.get_remaining_time_in_millis()) - 100) / 1000
    delete_sleep_time = 30
    stack_set_name = os.environ['stack_set_name']
    lacework_account_name = os.environ['lacework_account_name']
    log_account_name = os.environ['log_account_name']
    audit_account_name = os.environ['audit_account_name']
    region_name = context.invoked_function_arn.split(":")[3]

    cloudformation_client = session.client("cloudformation")

    try:
        paginator = cloudformation_client.get_paginator("list_stack_instances")
        page_iterator = paginator.paginate(StackSetName=stack_set_name)
        stack_set_list = []
        account_list = []
        region_list = []
        for page in page_iterator:
            if "Summaries" in page:
                stack_set_list.extend(page['Summaries'])
        for instance in stack_set_list:
            account_list.append(instance['Account'])
            region_list.append(instance['Region'])
        region_list = list(set(region_list))
        account_list = list(set(account_list))
        logger.info("StackSet instances found in region(s): {}".format(region_list))
        logger.info("StackSet instances found in account(s): {}".format(account_list))

        if len(account_list) > 0:
            response = cloudformation_client.delete_stack_instances(
                StackSetName=stack_set_name,
                Accounts=account_list,
                Regions=region_list,
                RetainStacks=False)
            logger.info(response)

            wait_for_stack_set_operation(stack_set_name, response['OperationId'])

    except Exception as stack_instance_exception:
        logger.warning("Problem occurred while deleting, StackSet {} instances still exist : {}"
                       .format(stack_set_name, stack_instance_exception))

    try:
        response = cloudformation_client.delete_stack_set(StackSetName=stack_set_name)
        logger.info("StackSet {} template delete status {}".format(stack_set_name, response))
    except Exception as stack_set_exception:
        logger.warning("Problem occurred while deleting, StackSet {} still exist : {}".format(stack_set_name,
                                                                                              stack_set_exception))

    audit_stack_set_name = "Lacework-CloudTrail-Audit-Account-Setup-" + lacework_account_name
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
        logger.info("StackSet {} template delete status {}".format(audit_stack_set_response, response))
    except Exception as stack_set_exception:
        logger.warning("Problem occurred while deleting, StackSet {} still exist : {}".format(audit_stack_set_name,
                                                                                              stack_set_exception))
    log_stack_set_name = "Lacework-CloudTrail-Log-Account-Setup-" + lacework_account_name
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
            logger.warning("Log account with name {} was not found.")

    except Exception as delete_log_stack_exception:
        logger.warning(
            "Problem occurred while deleting, Lacework-CloudTrail-Log-Account-Setup still exist : {}".format(
                delete_log_stack_exception))

    try:
        log_stack_set_response = cloudformation_client.delete_stack_set(StackSetName=log_stack_set_name)
        logger.info("StackSet {} template delete status {}".format(log_stack_set_response, response))
    except Exception as stack_set_exception:
        logger.warning("Problem occurred while deleting, StackSet {} still exist : {}".format(log_stack_set_name,
                                                                                              stack_set_exception))

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


def setup_initial_access_token(lacework_account_name, lacework_api_credentials):
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

        request_payload = '''
        {{
            "keyId": "{}", 
            "expiryTime": 86400
        }}
        '''.format(access_key_id)
        logger.debug('Generate access key payload : {}'.format(json.dumps(request_payload)))

        response = requests.post("https://" + lacework_account_name + ".lacework.net/api/v2/access/tokens",
                                 headers={'X-LW-UAKS': secret_key, 'content-type': 'application/json'},
                                 verify=True, data=request_payload)
        logger.info('API response code : {}'.format(response.status_code))
        logger.debug('API response : {}'.format(response.text))
        if response.status_code == 201:
            payload_response = response.json()
            expires_at = payload_response['expiresAt']
            token = payload_response['token']
            secret_string_dict['AccessToken'] = token
            secret_string_dict['TokenExpiry'] = expires_at
            secret_client.update_secret(SecretId=lacework_api_credentials, SecretString=json.dumps(secret_string_dict))
            logger.info("new access token save to secrets manager.")
            return token
        else:
            logger.error("Generate access key failure {} {}".format(response.status_code, response.text))
            return None
    except Exception as e:
        logger.error("Error setting up initial access token {}".format(e))
        return None


def setup_cloudtrail(lacework_account_name, region_name, management_account_id, log_account_name, log_account_template,
                     audit_account_name, audit_account_template, access_token, external_id):
    logger.info("setup.setup_cloudtrail called.")

    log_account_id = get_account_id_by_name(log_account_name)
    if log_account_id is None:
        logger.error("Log account with name {} was not found.")
        raise Exception

    audit_account_id = get_account_id_by_name(audit_account_name)
    if audit_account_id is None:
        logger.error("Audit account with name {} was not found.")
        raise Exception

    try:
        cloudtrail_client = boto3.client('cloudtrail')
        trail = cloudtrail_client.get_trail(
            Name="aws-controltower-BaselineCloudTrail"
        )
        cloudtrail_s3_bucket = trail['Trail']['S3BucketName']
        cloudtrail_sns_topic = trail['Trail']['SnsTopicARN']
        logger.info("Existing trail: s3: {} topic: {}".format(cloudtrail_s3_bucket, cloudtrail_sns_topic))
    except Exception as trail_exception:
        logger.error("Error getting cloudtrail aws-controltower-BaselineCloudTrail {}.".format(trail_exception))
        raise trail_exception

    sqs_queue_url = "https://sqs." + region_name + ".amazonaws.com/" + audit_account_id + "/" + lacework_account_name + "-laceworkcws"

    cloudformation_client = session.client("cloudformation")

    try:
        audit_stack_set_name = "Lacework-CloudTrail-Audit-Account-Setup-" + lacework_account_name
        cloudformation_client.describe_stack_set(StackSetName=audit_stack_set_name)
        logger.info("Stack set {} already exist".format(audit_stack_set_name))
    except Exception as describe_exception:
        logger.info("Stack set {} does not exist, creating it now. {}".format(audit_stack_set_name, describe_exception))
        try:
            audit_role = "arn:aws:iam::" + management_account_id + ":role/service-role/AWSControlTowerStackSetRole"
            logger.info("Using role {} to create stack set url {}".format(audit_role, audit_account_template))
            cloudformation_client.create_stack_set(
                StackSetName=audit_stack_set_name,
                Description=DESCRIPTION,
                TemplateURL=audit_account_template,
                Parameters=[
                    {
                        "ParameterKey": "ResourceNamePrefix",
                        "ParameterValue": lacework_account_name,
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

            logger.info("Audit stack set instance created {}".format(audit_stack_instance_response))
        except Exception as create_exception:
            logger.error("Error creating audit account stack {}.".format(create_exception))
            raise create_exception

    try:
        log_stack_set_name = "Lacework-CloudTrail-Log-Account-Setup-" + lacework_account_name
        cloudformation_client.describe_stack_set(StackSetName=log_stack_set_name)
        logger.info("Stack set {} already exist".format(log_stack_set_name))
    except Exception as describe_exception:
        logger.info("Stack set {} does not exist, creating it now. {}".format(log_stack_set_name, describe_exception))
        try:
            sqs_queue_url = "https://sqs." + region_name + ".amazonaws.com/" + audit_account_id + "/" + lacework_account_name + "-laceworkcws"
            logger.info("SQS queue url is {}".format(sqs_queue_url))
            log_role = "arn:aws:iam::" + management_account_id + ":role/service-role/AWSControlTowerStackSetRole"
            logger.info("Using role {} to create stack set url {}".format(log_role, log_account_template))
            cloudformation_client.create_stack_set(
                StackSetName=log_stack_set_name,
                Description=DESCRIPTION,
                TemplateURL=log_account_template,
                Parameters=[
                    {
                        "ParameterKey": "ResourceNamePrefix",
                        "ParameterValue": lacework_account_name,
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

            logger.info("Log stack set instance created {}".format(log_stack_instance_response))
        except Exception as create_exception:
            logger.error("Error creating log account stack {}.".format(create_exception))
            raise create_exception


def setup_config(stack_set_name, lacework_account_name, lacework_account_sns, existing_accounts,
                 member_account_template,
                 management_account_id, region_name, access_token, external_id):
    logger.info("setup.setup_config called.")
    cloudformation_client = session.client("cloudformation")
    try:
        cloudformation_client.describe_stack_set(StackSetName=stack_set_name)
        logger.info("Stack set {} already exist".format(stack_set_name))
    except Exception as describe_exception:
        logger.info("Stack set {} does not exist, creating it now. {}".format(stack_set_name, describe_exception))
        management_role = "arn:aws:iam::" + management_account_id + ":role/service-role/AWSControlTowerStackSetRole"
        logger.info("Using role {} to create stack {}".format(management_role, stack_set_name))
        cloudformation_client.create_stack_set(
            StackSetName=stack_set_name,
            Description="Lacework's cloud-native threat detection, compliance, behavioral anomaly detection, "
                        "and automated AWS security monitoring.",
            TemplateURL=member_account_template,
            Parameters=[
                {
                    "ParameterKey": "ResourceNamePrefix",
                    "ParameterValue": lacework_account_name,
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
                }
            ],
            Capabilities=[
                "CAPABILITY_NAMED_IAM"
            ],
            AdministrationRoleARN=management_role,
            ExecutionRoleName="AWSControlTowerExecution")

        try:
            cloudformation_client.describe_stack_set(StackSetName=stack_set_name)
            logger.info("StackSet {} deployed".format(stack_set_name))
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
                        account_list.append(inst['Account'])

                logger.info("Accounts to deploy {}.".format(account_list))
                if len(account_list) > 0:
                    logger.info("New accounts : {}".format(account_list))
                    sns_client = session.client("sns")
                    message_body = {stack_set_name: {"target_accounts": account_list, "target_regions": [region_name]}}
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
