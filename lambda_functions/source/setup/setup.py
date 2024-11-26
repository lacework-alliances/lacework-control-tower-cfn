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
import json
import logging
import os
import random
import string

import boto3
import urllib3
from crhelper import CfnResource

from aws import is_account_active, wait_for_stack_set_operation, get_account_id_by_name, send_cfn_fail, \
    send_cfn_success, get_org_for_account, create_stack_set_instances, delete_stack_set_instances, get_stack_tags, \
    stack_set_exists
from honeycomb import send_honeycomb_event
from lacework import setup_initial_access_token, get_access_token, add_lw_cloud_account_for_ct, delete_lw_cloud_account, \
    get_lacework_environment_variables
from util import error_exception

HONEY_API_KEY = "$HONEY_KEY"
DATASET = "$DATASET"
BUILD_VERSION = "$BUILD"


LOG_NAME_PREFIX = "Lacework-Control-Tower-CloudTrail-Log-Account-"
AUDIT_NAME_PREFIX = "Lacework-Control-Tower-CloudTrail-Audit-Account-"
CONFIG_NAME_PREFIX = "Lacework-Control-Tower-Config-Member-"

DESCRIPTION = "Lacework's cloud-native threat detection, compliance, behavioral anomaly detection, "
"and automated AWS security monitoring."

http = urllib3.PoolManager()

LOGLEVEL = os.environ.get('LOGLEVEL', logging.INFO)
logger = logging.getLogger()
logger.setLevel(LOGLEVEL)

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
    send_honeycomb_event(HONEY_API_KEY, DATASET, BUILD_VERSION, lacework_account_name, "create started",
                         lacework_sub_account_name, get_lacework_environment_variables())

    if not lacework_sub_account_name:
        logger.info("Sub account was not specified.")

    logger.info(
        "Lacework URL: {}, Lacework account: {}, Lacework Sub Account: {}".format(
            lacework_url,
            lacework_account_name,
            lacework_sub_account_name))

    lacework_account_sns = os.environ['lacework_account_sns']
    capability_type = os.environ['capability_type']
    existing_accounts = os.environ['existing_accounts']
    log_account_name = os.environ['log_account_name']
    kms_key_id_arn = os.environ['kms_key_id_arn']
    log_account_template = os.environ['log_account_template']
    audit_account_name = os.environ['audit_account_name']
    audit_account_template = os.environ['audit_account_template']
    member_account_template = os.environ['member_account_template']
    existing_cloudtrail = os.environ['existing_cloudtrail']
    management_account_id = context.invoked_function_arn.split(":")[4]
    region_name = context.invoked_function_arn.split(":")[3]

    try:
        access_token = setup_initial_access_token(lacework_url, lacework_api_credentials)

        if "CloudTrail" in capability_type:
            setup_cloudtrail(lacework_url, lacework_sub_account_name, region_name,
                             management_account_id,
                             log_account_name,
                             kms_key_id_arn,
                             log_account_template,
                             audit_account_name,
                             audit_account_template, access_token, existing_cloudtrail)
        if "Config" in capability_type:
            setup_config(lacework_account_name, lacework_sub_account_name,
                         lacework_account_sns,
                         existing_accounts,
                         member_account_template,
                         management_account_id,
                         region_name)

    except Exception as setup_exception:
        send_cfn_fail(event, context, "Setup failed {}.".format(setup_exception))
        return None

    send_honeycomb_event(HONEY_API_KEY, DATASET, BUILD_VERSION, lacework_account_name, "create completed",
                         lacework_sub_account_name)
    send_cfn_success(event, context)
    return None


@helper.delete  # crhelper method to delete stack set and stack instances
def delete(event, context):
    logger.info("setup.delete called.")
    lacework_url = os.environ['lacework_url']
    lacework_account_name = get_account_from_url(lacework_url)
    lacework_sub_account_name = os.environ['lacework_sub_account_name']
    lacework_org_sub_account_names = os.environ['lacework_org_sub_account_names']
    log_account_name = os.environ['log_account_name']
    audit_account_name = os.environ['audit_account_name']
    region_name = context.invoked_function_arn.split(":")[3]
    lacework_api_credentials = os.environ['lacework_api_credentials']
    config_stack_set_name = CONFIG_NAME_PREFIX + \
                            (lacework_account_name if not lacework_sub_account_name else lacework_sub_account_name)

    send_honeycomb_event(HONEY_API_KEY, DATASET, BUILD_VERSION, lacework_account_name, "delete started",
                         lacework_sub_account_name)

    cloudformation_client = boto3.client("cloudformation")

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
                if is_account_active(acct):
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
            delete_stack_set_instances(config_stack_set_name, account_list, region_list)

            access_token = get_access_token(lacework_api_credentials)
            if access_token is None:
                logger.warning("Unable to get Lacework access token. Failed to delete Config cloud accounts.")
            else:
                for acct in account_list:
                    org_name = get_org_for_account(acct, lacework_org_sub_account_names)
                    account_name = lacework_account_name if not lacework_sub_account_name else lacework_sub_account_name
                    sub_account_name = account_name if not org_name else org_name
                    delete_lw_cloud_account(CONFIG_NAME_PREFIX + acct, lacework_url, sub_account_name, access_token)
                    logger.info("Deleted acct {} to {} in Lacework".format(acct, sub_account_name))

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
    log_stack_set_name = LOG_NAME_PREFIX + (
        lacework_account_name if not lacework_sub_account_name else lacework_sub_account_name)
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
            logger.warning("Unable to get Lacework access token. Failed to delete cloud account {}."
                           .format(log_stack_set_name))
        else:
            delete_lw_cloud_account(log_stack_set_name, lacework_url, lacework_sub_account_name, access_token)
    except Exception as delete_exception:
        logger.warning("Failed to delete CloudTrail cloud account for {} {}.", lacework_account_name, delete_exception)

    send_honeycomb_event(HONEY_API_KEY, DATASET, BUILD_VERSION, lacework_account_name, "delete completed",
                         lacework_sub_account_name)
    send_cfn_success(event, context)
    return None


def setup_cloudtrail(lacework_url, lacework_sub_account_name, region_name,
                     management_account_id, log_account_name,
                     kms_key_id_arn, log_account_template, audit_account_name, audit_account_template, access_token,
                     existing_cloudtrail):
    logger.info("setup.setup_cloudtrail called.")

    log_account_id = get_account_id_by_name(log_account_name)
    lacework_account_name = get_account_from_url(lacework_url)
    external_id = "lweid:aws:v2:%s:%s:%s" % (lacework_account_name, log_account_id, ''.join(random.choices(string.ascii_uppercase + string.digits, k=10)))
    if log_account_id is None:
        raise error_exception("Log account with name {} was not found.".format(log_account_id),
                              HONEY_API_KEY, DATASET, BUILD_VERSION, lacework_account_name,
                              lacework_sub_account_name)
    else:
        logger.info("Log account {} has AWS ID {}.".format(log_account_name, log_account_id))

    audit_account_id = get_account_id_by_name(audit_account_name)
    if audit_account_id is None:
        raise error_exception("Audit account with name {} was not found.".format(audit_account_id),
                              HONEY_API_KEY, DATASET, BUILD_VERSION, lacework_account_name,
                              lacework_sub_account_name)
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
        raise error_exception("Error getting cloudtrail {} {}.".format(existing_cloudtrail, trail_exception),
                              HONEY_API_KEY, DATASET, BUILD_VERSION, lacework_account_name,
                              lacework_sub_account_name)

    cloudformation_client = boto3.client("cloudformation")

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
            log_role = os.environ['administration_role_arn']
            logger.info("Creating log stack {} with ResourceNamePrefix: {} ExternalID: {} "
                        "ExistingTrailBucketName: {} SqsQueueUrl: {} SqsQueueArn: {}".format(log_account_template,
                                                                                             lacework_account_name if not lacework_sub_account_name else lacework_sub_account_name,
                                                                                             cloudtrail_s3_bucket,
                                                                                             sqs_queue_url,
                                                                                             sqs_queue_arn))
            cfn_stack = os.environ['cfn_stack']
            cfn_stack_id = os.environ['cfn_stack_id']
            cfn_tags = get_stack_tags(cfn_stack, cfn_stack_id)
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
                        "ParameterKey": "ExistingTrailBucketName",
                        "ParameterValue": cloudtrail_s3_bucket,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string"
                    },
                    {
                        "ParameterKey": "KMSKeyIdentifierArn",
                        "ParameterValue": kms_key_id_arn if kms_key_id_arn else '',
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
                Tags=cfn_tags,
                Capabilities=[
                    "CAPABILITY_NAMED_IAM"
                ],
                AdministrationRoleARN=log_role,
                ExecutionRoleName=os.environ['execution_role_name'])

            try:
                cloudformation_client.describe_stack_set(StackSetName=log_stack_set_name)
                logger.info("StackSet {} deployed".format(log_stack_set_name))
            except cloudformation_client.exceptions.StackSetNotFoundException as describe_exception:
                raise error_exception("Exception getting new stack set, {}".format(describe_exception),
                                      HONEY_API_KEY, DATASET, BUILD_VERSION, lacework_account_name,
                                      lacework_sub_account_name)

            log_stack_instance_response = create_stack_set_instances(log_stack_set_name,
                                                                     [log_account_id], [region_name])

            wait_for_stack_set_operation(log_stack_set_name, log_stack_instance_response['OperationId'])

            logger.info("Log stack set instance created {}".format(log_stack_instance_response))
        except Exception as create_exception:
            raise error_exception("Error creating log account stack {}.".format(create_exception),
                                  HONEY_API_KEY, DATASET, BUILD_VERSION, lacework_account_name,
                                  lacework_sub_account_name)

    try:
        audit_stack_set_name = AUDIT_NAME_PREFIX + \
                               (lacework_account_name if not lacework_sub_account_name else lacework_sub_account_name)
        cloudformation_client.describe_stack_set(StackSetName=audit_stack_set_name)
        logger.info("Stack set {} already exists".format(audit_stack_set_name))
    except Exception as describe_exception:
        logger.info(
            "Stack set {} does not exist, creating it now. {}".format(audit_stack_set_name, describe_exception))
        try:
            logger.info("Existing trail: s3: {} topic: {}".format(cloudtrail_s3_bucket, cloudtrail_sns_topic))
            audit_role = os.environ['administration_role_arn']
            logger.info("Using role {} to create stack set url {}".format(audit_role, audit_account_template))
            cross_account_access_role = get_cross_account_access_role(lacework_account_name, lacework_sub_account_name,
                                                                      log_account_id)
            logger.info("Creating audit stack {} with ResourceNamePrefix: {} ExistingTrailTopicArn: {} "
                        "CrossAccountAccessRoleArn: {}".format(audit_account_template, lacework_account_name,
                                                               cloudtrail_sns_topic, cross_account_access_role))

            cfn_stack = os.environ['cfn_stack']
            cfn_stack_id = os.environ['cfn_stack_id']
            cfn_tags = get_stack_tags(cfn_stack, cfn_stack_id)
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
                Tags=cfn_tags,
                Capabilities=[
                    "CAPABILITY_NAMED_IAM"
                ],
                AdministrationRoleARN=audit_role,
                ExecutionRoleName=os.environ['execution_role_name'])

            try:
                cloudformation_client.describe_stack_set(StackSetName=audit_stack_set_name)
                logger.info("StackSet {} deployed".format(audit_stack_set_name))
            except cloudformation_client.exceptions.StackSetNotFoundException as describe_exception:
                raise error_exception("Exception getting new stack set, {}".format(describe_exception),
                                      HONEY_API_KEY, DATASET, BUILD_VERSION, lacework_account_name,
                                      lacework_sub_account_name)

            audit_stack_instance_response = create_stack_set_instances(audit_stack_set_name,
                                                                       [audit_account_id], [region_name])

            wait_for_stack_set_operation(audit_stack_set_name, audit_stack_instance_response['OperationId'])

            logger.info("Audit stack set instance created {}".format(audit_stack_instance_response))

            add_lw_cloud_account_for_ct(log_stack_set_name, lacework_url, lacework_sub_account_name,
                                        access_token, external_id,
                                        cross_account_access_role,
                                        sqs_queue_url)
            logger.info("Added CloudTrail account to Lacework {}".format(lacework_url))
        except Exception as create_exception:
            raise error_exception("Error creating audit account stack {}.".format(create_exception),
                                  HONEY_API_KEY, DATASET, BUILD_VERSION, lacework_account_name,
                                  lacework_sub_account_name)


def setup_config(lacework_account_name, lacework_sub_account_name,
                 lacework_account_sns,
                 existing_accounts,
                 member_account_template,
                 management_account_id, region_name):
    logger.info("setup.setup_config called.")
    cloudformation_client = boto3.client("cloudformation")
    try:
        config_stack_set_name = CONFIG_NAME_PREFIX + \
                                (lacework_account_name if not lacework_sub_account_name else lacework_sub_account_name)
        cloudformation_client.describe_stack_set(StackSetName=config_stack_set_name)
        logger.info("Stack set {} already exist".format(config_stack_set_name))
    except Exception as describe_exception:
        logger.info(
            "Stack set {} does not exist, creating it now. {}".format(config_stack_set_name, describe_exception))
        management_role = os.environ['administration_role_arn']
        logger.info("Using role {} to create stack {}".format(management_role, config_stack_set_name))
        logger.info("Creating config stack with ResourceNamePrefix: {}".format(lacework_account_name))
        resource_name_prefix = lacework_account_name if not lacework_sub_account_name else lacework_sub_account_name
        cfn_stack = os.environ['cfn_stack']
        cfn_stack_id = os.environ['cfn_stack_id']
        cfn_tags = get_stack_tags(cfn_stack, cfn_stack_id)
        external_suffix = os.environ['external_suffix']
        cloudformation_client.create_stack_set(
            StackSetName=config_stack_set_name,
            Description="Lacework's cloud-native threat detection, compliance, behavioral anomaly detection, "
                        "and automated AWS security monitoring.",
            TemplateURL=member_account_template,
            Parameters=[
                {
                    "ParameterKey": "ResourceNamePrefix",
                    "ParameterValue": resource_name_prefix,
                    "UsePreviousValue": False,
                    "ResolvedValue": "string"
                },
                {
                    "ParameterKey": "LaceworkAccountName",
                    "ParameterValue": lacework_account_name,
                    "UsePreviousValue": False,
                    "ResolvedValue": "string"
                },
                {
                    "ParameterKey": "ExternalSuffix",
                    "ParameterValue": external_suffix,
                    "UsePreviousValue": False,
                    "ResolvedValue": "string"
                }
            ],
            Tags=cfn_tags,
            Capabilities=[
                "CAPABILITY_NAMED_IAM"
            ],
            AdministrationRoleARN=management_role,
            ExecutionRoleName=os.environ['execution_role_name'])

        try:
            cloudformation_client.describe_stack_set(StackSetName=config_stack_set_name)
            logger.info("StackSet {} deployed".format(config_stack_set_name))
        except cloudformation_client.exceptions.StackSetNotFoundException as describe_exception:
            raise error_exception("Exception getting new stack set, {}".format(describe_exception),
                                  HONEY_API_KEY, DATASET, BUILD_VERSION, lacework_account_name,
                                  lacework_sub_account_name)

        if existing_accounts == "Yes":
            logger.info("Chose to deploy to existing accounts.")
            try:
                ct_cloudtrail_stack = "AWSControlTowerBP-BASELINE-CONFIG"  # LZ3.0
                if not stack_set_exists(ct_cloudtrail_stack):
                    ct_cloudtrail_stack = "AWSControlTowerBP-BASELINE-CLOUDTRAIL"
                account_set = set()
                paginator = cloudformation_client.get_paginator('list_stack_instances')
                page_iterator = paginator.paginate(StackSetName=ct_cloudtrail_stack)
                for page in page_iterator:
                    for inst in page['Summaries']:
                        # logger.info("DEBUG Stack Set inst Details {}".format(inst))
                        account_set.add(inst['Account'])
                account_list = list(account_set)
                if len(account_list) > 0:
                    send_honeycomb_event(HONEY_API_KEY, DATASET, BUILD_VERSION, lacework_account_name,
                                         "add {} existing".format(len(account_list)), lacework_sub_account_name)
                    send_to_account_function(account_list, [region_name], config_stack_set_name, lacework_account_sns)
            except Exception as create_exception:
                raise error_exception("Exception creating stack instances with {}".format(create_exception),
                                      HONEY_API_KEY, DATASET, BUILD_VERSION, lacework_account_name,
                                      lacework_sub_account_name)
        else:
            logger.info("Chose NOT to deploy to existing accounts.")


def get_account_from_url(lacework_url):
    return lacework_url.split('.')[0]



def get_aws_account_name(account_id, org_client):
    logger.info("setup.get_aws_account_name called.")
    try:
        logger.info("Getting account Name for account id {}".format(account_id))
        response = org_client.describe_account(AccountId=account_id)
        logger.info("Account name for id {} is {}".format(account_id, response['Account']['Name']))
        return response['Account']['Name']
    except Exception as e:
        logger.warning(f"Error getting account name for {account_id}: {e}")
        return None


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


def send_to_account_function(account_list, region_list, config_stack_set_name, lacework_account_sns):
    logger.info("setup.send_to_account_function accounts: {}".format(account_list))
    sns_client = boto3.client("sns")
    message_body = {
        config_stack_set_name: {"target_accounts": account_list, "target_regions": region_list}}
    try:
        sns_response = sns_client.publish(
            TopicArn=lacework_account_sns,
            Message=json.dumps(message_body))

        logger.info("Queued for stackset instance creation: {}".format(sns_response))
    except Exception as sns_exception:
        raise error_exception(
            "Failed to send queue for stackset instance creation: {}".format(sns_exception))
