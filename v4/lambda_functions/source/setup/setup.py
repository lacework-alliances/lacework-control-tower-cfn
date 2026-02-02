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


from aws import (
    is_account_active,
    wait_for_stack_set_operation,
    send_cfn_fail,
    send_cfn_success,
    get_account_name_by_id,
    get_org_for_account,
    create_stack_set_instances,
    delete_stack_set_instances,
    get_stack_tags,
    stack_set_exists,
)
from telemetry import send_lacework_telemetry_event
from lacework import (
    setup_initial_access_token,
    get_access_token,
    add_lw_cloud_account_for_ct,
    delete_lw_cloud_account,
    get_lacework_environment_variables,
)
from util import error_exception

DATASET = "$DATASET"
BUILD_VERSION = "$BUILD"

integration_prefix = "Lacework-Control-Tower-"
if os.environ.get("lacework_integration_name_prefix") is not None:
    integration_prefix = str(os.environ.get("lacework_integration_name_prefix"))

LOG_NAME_PREFIX = integration_prefix + "CloudTrail-Log-Archive-"
AUDIT_NAME_PREFIX = integration_prefix + "CloudTrail-Audit-"
CONFIG_NAME_PREFIX = integration_prefix + "Config-Member-"

DESCRIPTION = "Lacework's cloud-native threat detection, compliance, behavioral anomaly detection, "
"and automated AWS security monitoring."

http = urllib3.PoolManager()

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOGLEVEL", logging.INFO))

helper = CfnResource(
    json_logging=False, log_level="INFO", boto_level="CRITICAL", sleep_on_delete=15
)


def lambda_handler(event, context):
    logger.info("setup.lambda_handler called.")
    logger.info(json.dumps(event))
    try:
        if "RequestType" in event:
            helper(event, context)
    except Exception as e:
        helper.init_failure(e)


@helper.create
@helper.update
def create(event, context):
    logger.info("setup.create called.")
    logger.info(json.dumps(event))

    lacework_url = os.environ["lacework_url"]
    lacework_account_name = os.environ["lacework_account_name"]
    lacework_sub_account_name = os.environ["lacework_sub_account_name"]
    lacework_api_credentials = os.environ["lacework_api_credentials"]

    capability_type = os.environ["capability_type"]
    monitor_existing_accounts = os.environ["monitor_existing_accounts"]
    existing_cloudtrail = os.environ["existing_cloudtrail"]
    kms_key_id_arn = os.environ["kms_key_id_arn"]

    region_name = context.invoked_function_arn.split(":")[3]
    management_account_id = context.invoked_function_arn.split(":")[4]

    # SNS topic ARN created by Lacework in the management account to trigger account.py for member accounts
    lacework_account_sns = os.environ["lacework_account_sns"]

    log_account_id = os.environ["log_account_id"]
    audit_account_id = os.environ["audit_account_id"]
    log_account_template = os.environ["log_account_template"]
    audit_account_template = os.environ["audit_account_template"]
    member_account_template = os.environ["member_account_template"]

    lacework_env_vars = get_lacework_environment_variables()
    logger.info(f"Lacework environment variables: {lacework_env_vars}")

    # The IAM role in the management account used to create/update an StackSet
    cfn_role_arn = f"arn:aws:iam::{management_account_id}:role/service-role/AWSControlTowerStackSetRole"

    try:
        access_token = setup_initial_access_token(
            lacework_url, lacework_api_credentials
        )
        send_lacework_telemetry_event(
            DATASET,
            BUILD_VERSION,
            lacework_account_name,
            f"create started: {lacework_env_vars}",
            "setup.create",
            access_token,
            lacework_sub_account_name,
        )
        if "CloudTrail" in capability_type:
            setup_cloudtrail(
                lacework_url,
                lacework_account_name,
                lacework_sub_account_name,
                region_name,
                management_account_id,
                cfn_role_arn,
                log_account_id,
                kms_key_id_arn,
                log_account_template,
                audit_account_id,
                audit_account_template,
                access_token,
                existing_cloudtrail,
            )
        if "Config" in capability_type:
            setup_config(
                lacework_account_name,
                lacework_sub_account_name,
                lacework_account_sns,
                monitor_existing_accounts,
                member_account_template,
                cfn_role_arn,
                region_name,
                access_token,
            )
    except Exception as e:
        send_cfn_fail(event, context, f"setup.create failed: {e}")
        return None

    send_lacework_telemetry_event(
        DATASET,
        BUILD_VERSION,
        lacework_account_name,
        "create completed",
        "setup.create",
        access_token,
        lacework_sub_account_name,
    )
    send_cfn_success(event, context)
    return None


@helper.delete  # crhelper method to delete StackSet and stack instances
def delete(event, context):
    logger.info("setup.delete called.")

    lacework_url = os.environ["lacework_url"]
    lacework_account_name = os.environ["lacework_account_name"]
    lacework_sub_account_name = os.environ["lacework_sub_account_name"]
    lacework_org_sub_account_names = os.environ["lacework_org_sub_account_names"]
    lacework_api_credentials = os.environ["lacework_api_credentials"]

    region_name = context.invoked_function_arn.split(":")[3]
    log_account_id = os.environ["log_account_id"]
    audit_account_id = os.environ["audit_account_id"]

    resource_name_prefix = (
        lacework_account_name
        if not lacework_sub_account_name
        else lacework_sub_account_name
    )
    log_stack_set_name = LOG_NAME_PREFIX + resource_name_prefix
    audit_stack_set_name = AUDIT_NAME_PREFIX + resource_name_prefix
    config_stack_set_name = CONFIG_NAME_PREFIX + resource_name_prefix

    access_token = None

    try:
        access_token = get_access_token(lacework_api_credentials)
    except Exception as e:
        # Continue deletion even if we cannot get access token
        logger.warning(f"Failed to get Lacework access token: {e}")

    send_lacework_telemetry_event(
        DATASET,
        BUILD_VERSION,
        lacework_account_name,
        "delete started",
        "setup.delete",
        access_token,
        lacework_sub_account_name,
    )

    cloudformation_client = boto3.client("cloudformation")

    try:
        paginator = cloudformation_client.get_paginator("list_stack_instances")
        page_iterator = paginator.paginate(StackSetName=config_stack_set_name)
        stack_set_list = []
        account_list = []
        region_list = []
        for page in page_iterator:
            if "Summaries" in page:
                stack_set_list.extend(page["Summaries"])
        for instance in stack_set_list:
            acct = instance["Account"]
            region = instance["Region"]
            try:
                if is_account_active(acct):
                    account_list.append(acct)
                    region_list.append(region)
                    logger.info("Adding acct {}".format(acct))
                else:
                    logger.info("Skipping acct {}".format(acct))
            except Exception as e:
                logger.warning(f"Account status exception for acct {acct} {e}")

        region_list = list(set(region_list))
        account_list = list(set(account_list))

        logger.info("StackSet instances found in region(s): {}".format(region_list))
        logger.info("StackSet instances found in account(s): {}".format(account_list))

        if len(account_list) > 0:
            delete_stack_set_instances(config_stack_set_name, account_list, region_list)

            if access_token is None:
                logger.warning(
                    "Unable to get Lacework access token. Failed to delete Config cloud accounts."
                )
            else:
                for acct in account_list:
                    org_name = get_org_for_account(acct, lacework_org_sub_account_names)
                    account_name = (
                        lacework_account_name
                        if not lacework_sub_account_name
                        else lacework_sub_account_name
                    )
                    sub_account_name = account_name if not org_name else org_name
                    delete_lw_cloud_account(
                        CONFIG_NAME_PREFIX + acct,
                        lacework_url,
                        sub_account_name,
                        access_token,
                    )
    except Exception as e:
        logger.warning(
            f"Problem occurred while deleting, StackSet {config_stack_set_name} instances still exist: {e}"
        )

    try:
        response = cloudformation_client.delete_stack_set(
            StackSetName=config_stack_set_name
        )
        logger.info(f"StackSet {config_stack_set_name} delete status: {response}")
    except Exception as e:
        logger.warning(
            f"Problem occurred while deleting, StackSet {config_stack_set_name} still exist : {e}"
        )

    try:
        audit_stack_instance_response = cloudformation_client.delete_stack_instances(
            StackSetName=audit_stack_set_name,
            Accounts=[audit_account_id],
            Regions=[region_name],
            RetainStacks=False,
        )
        logger.info(audit_stack_instance_response)
        wait_for_stack_set_operation(
            audit_stack_set_name, audit_stack_instance_response["OperationId"]
        )
    except Exception as e:
        logger.warning(
            f"Problem occurred while deleting, StackSet {audit_stack_set_name} instances still exist: {e}"
        )

    try:
        audit_stack_set_response = cloudformation_client.delete_stack_set(
            StackSetName=audit_stack_set_name
        )
        logger.info(
            f"StackSet {audit_stack_set_name} deletion status: {audit_stack_set_response}"
        )
    except Exception as e:
        logger.warning(
            f"Problem occurred while deleting StackSet {audit_stack_set_name}: {e}"
        )

    try:
        log_stack_instance_response = cloudformation_client.delete_stack_instances(
            StackSetName=log_stack_set_name,
            Accounts=[log_account_id],
            Regions=[region_name],
            RetainStacks=False,
        )
        logger.info(log_stack_instance_response)
        wait_for_stack_set_operation(
            log_stack_set_name, log_stack_instance_response["OperationId"]
        )
    except Exception as e:
        logger.warning(
            f"Problem occurred while deleting, StackSet {log_stack_set_name} instances still exist: {e}"
        )

    try:
        log_stack_set_response = cloudformation_client.delete_stack_set(
            StackSetName=log_stack_set_name
        )
        logger.info(
            f"StackSet {log_stack_set_name} delete status: {log_stack_set_response}"
        )
    except Exception as stack_set_exception:
        logger.warning(
            f"Problem occurred while deleting, StackSet {log_stack_set_name} still exist : {stack_set_exception}"
        )

    try:
        delete_lw_cloud_account(
            log_stack_set_name,
            lacework_url,
            lacework_sub_account_name,
            access_token,
        )
    except Exception as e:
        logger.warning(
            f"Failed to delete Lacework  cloud account CloudTrail integration for {log_stack_set_name}: {e}"
        )

    send_lacework_telemetry_event(
        DATASET,
        BUILD_VERSION,
        lacework_account_name,
        "delete completed",
        "setup.delete",
        access_token,
        lacework_sub_account_name,
    )
    send_cfn_success(event, context)
    return None


def setup_cloudtrail(
    lacework_url,
    lacework_account_name,
    lacework_sub_account_name,
    region_name,
    management_account_id,
    cfn_role_arn,
    log_account_id,
    kms_key_id_arn,
    log_account_template,
    audit_account_id,
    audit_account_template,
    access_token,
    existing_cloudtrail,
):
    logger.info("setup.setup_cloudtrail called.")

    cfn_stack = os.environ["cfn_stack"]
    cfn_stack_id = os.environ["cfn_stack_id"]
    cfn_tags = get_stack_tags(cfn_stack, cfn_stack_id)

    resource_name_prefix = (
        lacework_account_name
        if not lacework_sub_account_name
        else lacework_sub_account_name
    )
    log_stack_set_name = LOG_NAME_PREFIX + resource_name_prefix
    audit_stack_set_name = AUDIT_NAME_PREFIX + resource_name_prefix

    cloudtrail_sns_topic_arn = ""
    cloudtrail_s3_bucket_name = ""

    cross_account_access_role = (
        f"arn:aws:iam::{log_account_id}:role/{resource_name_prefix}-laceworkcwssarole"
    )
    sqs_queue_url = f"https://sqs.{region_name}.amazonaws.com/{audit_account_id}/{resource_name_prefix}-laceworkcws"
    sqs_queue_arn = f"arn:aws:sqs:{region_name}:{audit_account_id}:{resource_name_prefix}-laceworkcws"

    external_id = "lweid:aws:v2:%s:%s:%s" % (
        lacework_account_name,
        log_account_id,
        "".join(random.choices(string.ascii_uppercase + string.digits, k=10)),
    )

    # Get CloudTrail SNS topic ARN and S3 bucket name if they exist
    try:
        cloudtrail_client = boto3.client("cloudtrail")
        trail = cloudtrail_client.get_trail(Name=existing_cloudtrail)
        cloudtrail_s3_bucket_name = trail["Trail"]["S3BucketName"]
        # We do not create CloudTrail S3 buckets for customer, so if one does not exist, raise error
        if not cloudtrail_s3_bucket_name:
            raise Exception(
                f"CloudTrail {existing_cloudtrail} does not have an S3 bucket.",
            )
        if "SnsTopicARN" in trail["Trail"]:
            cloudtrail_sns_topic_arn = trail["Trail"]["SnsTopicARN"]
            logger.info(
                f"CloudTrail has existing SNS Topic: {cloudtrail_sns_topic_arn}"
            )
        else:
            logger.info(
                "CloudTrail has no existing SNS Topic, will create one in Log Archive account."
            )
    except Exception as e:
        raise error_exception(
            f"Error getting details of CloudTrail {existing_cloudtrail} {e}.",
            access_token,
            DATASET,
            BUILD_VERSION,
            lacework_account_name,
            "setup.setup_cloudtrail",
            lacework_sub_account_name,
        )

    cloudformation_client = boto3.client("cloudformation")

    # Create Log Archive account StackSet
    try:
        cloudformation_client.describe_stack_set(StackSetName=log_stack_set_name)
        logger.info("StackSet {} already exist".format(log_stack_set_name))
    except Exception as e:
        logger.info(
            f"StackSet {log_stack_set_name} does not exist, creating it now. {e}"
        )
        try:
            logger.info(
                f"Creating Log Archive StackSet {log_stack_set_name}"
                f"CloudTrailS3BucketName: {cloudtrail_s3_bucket_name} SqsQueueUrl: {sqs_queue_url} SqsQueueArn: {sqs_queue_arn}"
            )

            cloudformation_client.create_stack_set(
                StackSetName=log_stack_set_name,
                Description=DESCRIPTION,
                TemplateURL=log_account_template,
                Parameters=[
                    {
                        "ParameterKey": "ResourceNamePrefix",
                        "ParameterValue": resource_name_prefix,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string",
                    },
                    {
                        "ParameterKey": "ExternalID",
                        "ParameterValue": external_id,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string",
                    },
                    {
                        "ParameterKey": "CloudTrailS3BucketName",
                        "ParameterValue": cloudtrail_s3_bucket_name,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string",
                    },
                    {
                        "ParameterKey": "CloudTrailSnsTopicArn",
                        "ParameterValue": cloudtrail_sns_topic_arn,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string",
                    },
                    {
                        "ParameterKey": "KMSKeyIdArn",
                        "ParameterValue": kms_key_id_arn if kms_key_id_arn else "",
                        "UsePreviousValue": False,
                        "ResolvedValue": "string",
                    },
                    {
                        "ParameterKey": "SqsQueueUrl",
                        "ParameterValue": sqs_queue_url,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string",
                    },
                    {
                        "ParameterKey": "SqsQueueArn",
                        "ParameterValue": sqs_queue_arn,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string",
                    },
                    {
                        "ParameterKey": "AuditAccountId",
                        "ParameterValue": audit_account_id,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string",
                    },
                ],
                Tags=cfn_tags,
                Capabilities=["CAPABILITY_NAMED_IAM"],
                AdministrationRoleARN=cfn_role_arn,
                ExecutionRoleName="AWSControlTowerExecution",
            )

            try:
                cloudformation_client.describe_stack_set(
                    StackSetName=log_stack_set_name
                )
                logger.info("StackSet {} deployed".format(log_stack_set_name))
            except cloudformation_client.exceptions.StackSetNotFoundException as e:
                raise error_exception(
                    f"Exception getting new StackSet, {e}",
                    access_token,
                    DATASET,
                    BUILD_VERSION,
                    lacework_account_name,
                    "setup",
                    lacework_sub_account_name,
                )

            log_stack_instance_response = create_stack_set_instances(
                log_stack_set_name, [log_account_id], [region_name]
            )

            wait_for_stack_set_operation(
                log_stack_set_name, log_stack_instance_response["OperationId"]
            )

            logger.info(
                f"Log Archive StackSet instance created: {log_stack_instance_response}"
            )

            # If cloudtrail_sns_topic_arn was empty, a new SNS topic will be created in the Log Archive account
            # We need to get the new SNS topic arn and update cloudtrail_sns_topic_arn
            if cloudtrail_sns_topic_arn == "":
                try:
                    # Get the SNS Topic arn from Log Archive Stack outputs
                    stack_instances = cloudformation_client.list_stack_instances(
                        StackSetName=log_stack_set_name,
                        StackInstanceAccount=log_account_id,
                        StackInstanceRegion=region_name,
                    )
                    stack_id = stack_instances["Summaries"][0]["StackId"]

                    # Assume role in Log Archive account to describe Stack
                    sts_client = boto3.client("sts")
                    assumed_role = sts_client.assume_role(
                        RoleArn=f"arn:aws:iam::{log_account_id}:role/AWSControlTowerExecution",
                        RoleSessionName="LaceworkCloudTrailSetup",
                    )

                    log_cfn_client = boto3.client(
                        "cloudformation",
                        region_name=region_name,
                        aws_access_key_id=assumed_role["Credentials"]["AccessKeyId"],
                        aws_secret_access_key=assumed_role["Credentials"][
                            "SecretAccessKey"
                        ],
                        aws_session_token=assumed_role["Credentials"]["SessionToken"],
                    )

                    stack_response = log_cfn_client.describe_stacks(StackName=stack_id)
                    outputs = stack_response["Stacks"][0].get("Outputs", [])

                    new_sns_topic_arn = None
                    for output in outputs:
                        if output["OutputKey"] == "CloudTrailSnsTopicArn":
                            new_sns_topic_arn = output["OutputValue"]
                            break
                    if new_sns_topic_arn:
                        # update cloudtrail to use new sns topic
                        cloudtrail_client.update_trail(
                            Name=existing_cloudtrail, SnsTopicName=new_sns_topic_arn
                        )
                        cloudtrail_sns_topic_arn = new_sns_topic_arn
                        logger.info(
                            f"Updated CloudTrail {existing_cloudtrail} to use new SNS Topic: {new_sns_topic_arn}"
                        )
                    else:
                        raise Exception(
                            "Could not find CloudTrailSnsTopicArn output from Log Archive stack."
                        )
                except Exception as e:
                    raise error_exception(
                        f"Error updating CloudTrail with new SNS Topic: {e}",
                        access_token,
                        DATASET,
                        BUILD_VERSION,
                        lacework_account_name,
                        "setup.setup_cloudtrail",
                        lacework_sub_account_name,
                    )

        except Exception as create_exception:
            raise error_exception(
                "Error creating log account stack {}.".format(create_exception),
                access_token,
                DATASET,
                BUILD_VERSION,
                lacework_account_name,
                "setup.setup_cloudtrail",
                lacework_sub_account_name,
            )

    # Setup audit account StackSet
    try:
        cloudformation_client.describe_stack_set(StackSetName=audit_stack_set_name)
        logger.info("StackSet {} already exists".format(audit_stack_set_name))
    except Exception as e:
        logger.info(
            f"StackSet {audit_stack_set_name} does not exist, creating it now. {e}"
        )
        try:
            logger.info("Discovering Config bucket for Control Tower 4.0")
            config_s3_bucket_name = ""

            # Create session for audit account to find Config bucket
            sts_client = boto3.client("sts")
            audit_role_arn = (
                f"arn:aws:iam::{audit_account_id}:role/AWSControlTowerExecution"
            )
            assumed_role = sts_client.assume_role(
                RoleArn=audit_role_arn, RoleSessionName="LaceworkConfigDiscovery"
            )
            audit_session = boto3.Session(
                aws_access_key_id=assumed_role["Credentials"]["AccessKeyId"],
                aws_secret_access_key=assumed_role["Credentials"]["SecretAccessKey"],
                aws_session_token=assumed_role["Credentials"]["SessionToken"],
            )

            s3 = audit_session.client("s3", region_name=region_name)
            response = s3.list_buckets()
            for bucket in response["Buckets"]:
                if bucket["Name"].startswith("aws-controltower-config-logs-"):
                    config_s3_bucket_name = bucket["Name"]
                    logger.info(
                        f"Found Config S3 Bucket in Audit Account: {bucket['Name']}"
                    )
                    break

            if not config_s3_bucket_name:
                raise Exception(
                    "Could not find aws-controltower-config-logs-* bucket in Audit Account."
                )

            logger.info(
                "Creating audit StackSet {}"
                "CrossAccountAccessRoleArn: {} CloudTrailSnsTopicArn: {} ConfigS3BucketName: {}".format(
                    audit_stack_set_name,
                    cloudtrail_sns_topic_arn,
                    cross_account_access_role,
                    config_s3_bucket_name,
                )
            )

            cloudformation_client.create_stack_set(
                StackSetName=audit_stack_set_name,
                Description=DESCRIPTION,
                TemplateURL=audit_account_template,
                Parameters=[
                    {
                        "ParameterKey": "ResourceNamePrefix",
                        "ParameterValue": resource_name_prefix,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string",
                    },
                    {
                        "ParameterKey": "CloudTrailSnsTopicArn",
                        "ParameterValue": cloudtrail_sns_topic_arn,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string",
                    },
                    {
                        "ParameterKey": "CrossAccountAccessRoleArn",
                        "ParameterValue": cross_account_access_role,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string",
                    },
                    {
                        "ParameterKey": "ConfigS3BucketName",
                        "ParameterValue": config_s3_bucket_name,
                        "UsePreviousValue": False,
                        "ResolvedValue": "string",
                    },
                ],
                Tags=cfn_tags,
                Capabilities=["CAPABILITY_NAMED_IAM"],
                AdministrationRoleARN=cfn_role_arn,
                ExecutionRoleName="AWSControlTowerExecution",
            )

            try:
                cloudformation_client.describe_stack_set(
                    StackSetName=audit_stack_set_name
                )
                logger.info("StackSet {} deployed".format(audit_stack_set_name))
            except cloudformation_client.exceptions.StackSetNotFoundException as e:
                raise error_exception(
                    f"Exception getting new StackSet, {e}",
                    access_token,
                    DATASET,
                    BUILD_VERSION,
                    lacework_account_name,
                    "setup.setup_cloudtrail",
                    lacework_sub_account_name,
                )

            audit_stack_instance_response = create_stack_set_instances(
                audit_stack_set_name, [audit_account_id], [region_name]
            )

            wait_for_stack_set_operation(
                audit_stack_set_name, audit_stack_instance_response["OperationId"]
            )
            logger.info(
                f"Audit StackSet instance created: {audit_stack_instance_response}"
            )

            add_lw_cloud_account_for_ct(
                log_stack_set_name,
                lacework_url,
                lacework_sub_account_name,
                access_token,
                external_id,
                cross_account_access_role,
                sqs_queue_url,
            )
        except Exception as e:
            raise error_exception(
                f"Error creating audit account stack {e}",
                access_token,
                DATASET,
                BUILD_VERSION,
                lacework_account_name,
                "setup.setup_cloudtrail",
                lacework_sub_account_name,
            )


def setup_config(
    lacework_account_name,
    lacework_sub_account_name,
    lacework_account_sns,
    monitor_existing_accounts,
    member_account_template,
    cfn_role_arn,
    region_name,
    access_token,
):
    logger.info("setup.setup_config called.")

    cfn_stack = os.environ["cfn_stack"]
    cfn_stack_id = os.environ["cfn_stack_id"]
    cfn_tags = get_stack_tags(cfn_stack, cfn_stack_id)
    external_suffix = os.environ["external_suffix"]

    resource_name_prefix = (
        lacework_account_name
        if not lacework_sub_account_name
        else lacework_sub_account_name
    )
    config_stack_set_name = CONFIG_NAME_PREFIX + resource_name_prefix

    cloudformation_client = boto3.client("cloudformation")

    try:
        cloudformation_client.describe_stack_set(StackSetName=config_stack_set_name)
        logger.info("StackSet {} already exist".format(config_stack_set_name))
    except Exception as e:
        logger.info(
            f"StackSet {config_stack_set_name} does not exist, creating it now. {e}"
        )

        cloudformation_client.create_stack_set(
            StackSetName=config_stack_set_name,
            Description=DESCRIPTION,
            TemplateURL=member_account_template,
            Parameters=[
                {
                    "ParameterKey": "ResourceNamePrefix",
                    "ParameterValue": resource_name_prefix,
                    "UsePreviousValue": False,
                    "ResolvedValue": "string",
                },
                {
                    "ParameterKey": "LaceworkAccountName",
                    "ParameterValue": lacework_account_name,
                    "UsePreviousValue": False,
                    "ResolvedValue": "string",
                },
                {
                    "ParameterKey": "ExternalSuffix",
                    "ParameterValue": external_suffix,
                    "UsePreviousValue": False,
                    "ResolvedValue": "string",
                },
            ],
            Tags=cfn_tags,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            AdministrationRoleARN=cfn_role_arn,
            ExecutionRoleName="AWSControlTowerExecution",
        )

        try:
            cloudformation_client.describe_stack_set(StackSetName=config_stack_set_name)
            logger.info("StackSet {} deployed".format(config_stack_set_name))
        except cloudformation_client.exceptions.StackSetNotFoundException as e:
            raise error_exception(
                f"Exception getting new StackSet, {e}",
                access_token,
                DATASET,
                BUILD_VERSION,
                lacework_account_name,
                "setup.setup_config",
                lacework_sub_account_name,
            )

        if monitor_existing_accounts == "Yes":
            logger.info("Chose to deploy to existing accounts.")
            try:
                ct_cloudtrail_stack = "AWSControlTowerBP-BASELINE-CONFIG"  # LZ3.0
                if not stack_set_exists(ct_cloudtrail_stack):
                    ct_cloudtrail_stack = "AWSControlTowerBP-BASELINE-CLOUDTRAIL"
                account_set = set()
                paginator = cloudformation_client.get_paginator("list_stack_instances")
                page_iterator = paginator.paginate(StackSetName=ct_cloudtrail_stack)
                for page in page_iterator:
                    for inst in page["Summaries"]:
                        account_set.add(inst["Account"])
                account_list = list(account_set)
                account_dict = {}
                for acct_id in account_list:
                    account_name = get_account_name_by_id(acct_id)
                    if account_name:
                        account_dict[acct_id] = account_name

                if len(account_list) > 0:
                    send_lacework_telemetry_event(
                        DATASET,
                        BUILD_VERSION,
                        lacework_account_name,
                        f"add {len(account_list)} existing accounts",
                        "setup.setup_config",
                        access_token,
                        lacework_sub_account_name,
                    )
                    send_to_account_function(
                        account_list,
                        account_dict,
                        [region_name],
                        config_stack_set_name,
                        lacework_account_sns,
                    )
            except Exception as e:
                raise error_exception(
                    f"Exception creating stack instances with {e}",
                    access_token,
                    DATASET,
                    BUILD_VERSION,
                    lacework_account_name,
                    "setup.setup_config",
                    lacework_sub_account_name,
                )
        else:
            logger.info("Chose NOT to deploy to existing accounts.")


def send_to_account_function(
    account_list, account_dict, region_list, config_stack_set_name, lacework_account_sns
):
    logger.info(f"setup.send_to_account_function called. Account list: {account_list}")
    sns_client = boto3.client("sns")
    message_body = {
        config_stack_set_name: {
            "target_accounts": account_list,
            "target_regions": region_list,
            "target_accounts_dict": account_dict,
        }
    }
    try:
        sns_response = sns_client.publish(
            TopicArn=lacework_account_sns, Message=json.dumps(message_body)
        )
        logger.info(f"Queued for StackSet instance creation: {sns_response}")
    except Exception as e:
        raise error_exception(
            f"Failed to send queue for StackSet instance creation: {e}"
        )
