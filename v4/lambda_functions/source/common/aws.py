import json
import logging
import os

import boto3
import time

import requests

RETRIES = 10
RETRY_WAIT = 60

SUCCESS = "SUCCESS"
FAILED = "FAILED"

STACK_SET_OPERATION_SUCCESS_STATES = ["SUCCEEDED"]
STACK_SET_OPERATION_RUNNING_STATES = ["RUNNING", "STOPPING"]

LOGLEVEL = os.environ.get('LOGLEVEL', logging.INFO)
logger = logging.getLogger()
logger.setLevel(LOGLEVEL)


def get_account_id_by_name(name):
    logger.info("aws.get_account_id_by_name called.")
    org_client = boto3.client('organizations')
    paginator = org_client.get_paginator("list_accounts")
    page_iterator = paginator.paginate()
    for page in page_iterator:
        for acct in page['Accounts']:
            if acct['Name'] == name:
                return acct['Id']

    return None


def is_account_valid(acct, orgs):
    logger.info("aws.is_account_valid called.")
    return is_account_active(acct) and is_account_in_orgs(acct, orgs)


def is_account_active(acct):
    logger.info("aws.is_account_active called.")
    org_client = boto3.client('organizations')
    try:
        response = org_client.describe_account(
            AccountId=acct
        )
        logger.info("Account {} is {}.".format(acct, response['Account']['Status']))
        return response['Account']['Status'] == "ACTIVE"
    except Exception as describe_exception:
        logger.warning("Exception getting account status on {} {}.".format(acct, describe_exception))
        return False


def get_org_tree_for_id(ou_acct_id):
    logger.info("aws.get_org_tree_for_account called.")
    org_tree = []
    org_client = boto3.client('organizations')
    try:
        while ou_acct_id:
            response = org_client.list_parents(
                ChildId=ou_acct_id,
                MaxResults=20
            )
            for parent in response['Parents']:
                if parent["Type"] == "ORGANIZATIONAL_UNIT":
                    ou_acct_id = parent["Id"]
                    org_name = org_client.describe_organizational_unit(
                        OrganizationalUnitId=ou_acct_id
                    )["OrganizationalUnit"]["Name"]
                    org_tree.append(org_name.lower())
                elif parent["Type"] == "ROOT":
                    ou_acct_id = False
                    break
        return org_tree
    except Exception as describe_exception:
        logger.error("Exception getting account org on {} {}.".format(id, describe_exception))
        return False


def is_account_in_orgs(acct, orgs):
    logger.info("aws.is_account_in_orgs called.")
    if not orgs:
        return True

    try:
        acct_orgs = get_org_tree_for_id(acct)

        if acct_orgs:
            org_list = [x.strip() for x in orgs.split(',')]
            for acct_org in acct_orgs:
                for org in org_list:
                    if org.lower() == acct_org.lower():
                        logger.info("Account {} is in org {}.".format(acct, org))
                        return True
            logger.info("Account {} is not in orgs {}.".format(acct, orgs))
            return False
        else:
            logger.info("Account {} is not in a AWS org?!?.".format(acct))
            return False

    except Exception as describe_exception:
        logger.error("Exception getting account org on {} {}.".format(acct, describe_exception))
        return False


def get_org_for_account(acct, orgs):
    logger.info("aws.get_org_for_account called.")
    if not orgs:
        return None

    try:
        acct_orgs = get_org_tree_for_id(acct)

        if acct_orgs:
            org_list = [x.strip() for x in orgs.split(',')]
            for acct_org in acct_orgs:
                for org in org_list:
                    if org.lower() == acct_org.lower():
                        logger.info("Account {} is in org {}.".format(acct, org))
                        return org
            logger.info("Account {} is not in orgs {}.".format(acct, orgs))
            return None
        else:
            logger.info("Account {} is not in a AWS org?!?.".format(acct))
            return None

    except Exception as describe_exception:
        logger.error("Exception getting account org on {} {}.".format(acct, describe_exception))
        return None


def create_stack_set_instances(stack_set_name, accounts, regions, parameter_overrides=[], retry=1):
    logger.info("aws.create_stack_set_instances called.")
    logger.info("Create stack name={} accounts={} regions={} parameter_overrides={} ".format(stack_set_name, accounts,
                                                                                             regions,
                                                                                             parameter_overrides))
    cloud_formation_client = boto3.client("cloudformation")
    try:
        return cloud_formation_client.create_stack_instances(StackSetName=stack_set_name,
                                                         Accounts=accounts,
                                                         Regions=regions,
                                                         ParameterOverrides=parameter_overrides,
                                                         OperationPreferences={
                                                             'RegionConcurrencyType': "PARALLEL",
                                                             'MaxConcurrentCount': 100,
                                                             'FailureToleranceCount': 999
                                                         })
    except Exception as e:
        if e.response['Error']['Code'] == 'OperationInProgressException':
            logger.info("StackSet {} already in progress.".format(stack_set_name))
            if retry < RETRIES:
                logger.info("Retrying in {} seconds.".format(retry * RETRY_WAIT))
                time.sleep(retry * RETRY_WAIT)
                return create_stack_set_instances(stack_set_name, accounts, regions, parameter_overrides, retry + 1)
            else:
                logger.error("Retried {} times. Giving up.".format(RETRIES))
                raise e


def delete_stack_set_instances(stack_set_name, account_list, region_list, retry=1):
    logger.info("aws.delete_stack_set_instances called.")
    try:
        cloud_formation_client = boto3.client("cloudformation")
        response = cloud_formation_client.delete_stack_instances(
            StackSetName=stack_set_name,
            Accounts=account_list,
            Regions=region_list,
            RetainStacks=False)
        logger.info(response)

        wait_for_stack_set_operation(stack_set_name, response['OperationId'])
    except Exception as e:
        if e.response['Error']['Code'] == 'OperationInProgressException':
            logger.info("StackSet {} already in progress.".format(stack_set_name))
            if retry < RETRIES:
                logger.info("Retrying in {} seconds.".format(retry * RETRY_WAIT))
                time.sleep(retry * RETRY_WAIT)
                delete_stack_set_instances(stack_set_name, account_list, region_list, retry + 1)
            else:
                logger.error("Retried {} times. Giving up.".format(RETRIES))
                raise e
        else:
            logger.error("Exception deleting stack set instances: {}".format(e))


def wait_for_stack_set_operation(stack_set_name, operation_id):
    logger.info("aws.wait_for_stack_set_operation called.")
    logger.info("Waiting for StackSet Operation {} on StackSet {} to finish".format(operation_id, stack_set_name))
    cloudformation_client = boto3.client("cloudformation")
    finished = False
    status = ""
    count = 1
    while not finished:
        time.sleep(count * RETRY_WAIT)
        status = \
            cloudformation_client.describe_stack_set_operation(StackSetName=stack_set_name, OperationId=operation_id)[
                "StackSetOperation"
            ]["Status"]
        if status in STACK_SET_OPERATION_RUNNING_STATES:
            logger.info("{} {} still running.".format(stack_set_name, operation_id))
        else:
            finished = True
        count += 1

    logger.info("StackSet Operation finished with Status: {}".format(status))
    if status not in STACK_SET_OPERATION_SUCCESS_STATES:
        return False
    else:
        return True


def stack_set_exists(stack_set_name):
    logger.info("aws.stack_set_exists called.")
    try:
        cfn_client = boto3.client("cloudformation")
        stack_set_result = cfn_client.describe_stack_set(
            StackSetName=stack_set_name,
        )

        logger.info("stack_set_result: {}".format(stack_set_result))
        return True
    except Exception as e:
        logger.error("Describe Stack Set error: {}.".format(e))
        return False


def stack_set_instance_exists(stack_set_name, account_id):
    logger.info("aws.stack_set_instance_exists called.")
    try:
        cfn_client = boto3.client("cloudformation")
        stack_set_result = cfn_client.list_stack_instances(
            StackSetName=stack_set_name,
            StackInstanceAccount=account_id,
        )

        logger.info("stack_set_result: {}".format(stack_set_result))
        if stack_set_result and "Summaries" in stack_set_result:
            stack_set_list = stack_set_result['Summaries']
            while "NextToken" in stack_set_result:
                stack_set_result = cfn_client.list_stack_set_instance(
                    NextToken=stack_set_result['NextToken']
                )
                stack_set_list.append(stack_set_result['Summaries'])

            logger.info("Stack instance for account {} found {} times.".format(account_id, len(stack_set_list)))
            return len(stack_set_list) > 0
        else:
            return False
    except Exception as e:
        logger.error("List Stack Instance error: {}.".format(e))
        return False


def list_stack_instance_by_account_region(stack_set_name, account_id, region):
    logger.info("aws.list_stack_instance_by_account_region called.")
    try:
        cfn_client = boto3.client("cloudformation")
        stack_set_result = cfn_client.list_stack_instances(
            StackSetName=stack_set_name,
            StackInstanceAccount=account_id,
            StackInstanceRegion=region
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


def get_stack_tags(stack_name, stack_id):
    logger.info("aws.get_stack_tags.")
    try:
        cfn_client = boto3.client("cloudformation")
        response = cfn_client.describe_stacks(
            StackName=stack_name
        )

        logger.info("stacks_result: {}".format(response))
        for stack in response['Stacks']:
            if stack["StackId"] == stack_id:
                return stack["Tags"]

        return []
    except Exception as e:
        logger.error("List Stack Instance error: {}.".format(e))
        return []


def send_cfn_fail(event, context, msg):
    logger.error(msg)
    send_cfn_response(event, context, FAILED, {"Message": msg})


def send_cfn_success(event, context):
    send_cfn_response(event, context, SUCCESS, {"Message": "SUCCESS"})


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
        response = requests.put(response_url, headers=headers, data=json_response_body)
        logger.info("CFN response status code: {}".format(response.status_code))

    except Exception as e:
        logger.error("send_cfn_response error {}".format(e))


def enable_cloudtrail_sns(trail_name, audit_account_id, region, management_account_id):
    """
    Enables SNS on CloudTrail to fix the "Silent CloudTrail" issue in Control Tower 4.0.
    
    Args:
        trail_name: Name of the CloudTrail
        audit_account_id: AWS account ID of the audit account
        region: AWS region
        
    Returns:
        True if successful, raises exception if failed
    """
    logger.info("aws.enable_cloudtrail_sns called.")
    try:
        sts_client = boto3.client('sts')
        audit_role_arn = f"arn:aws:iam::{audit_account_id}:role/AWSControlTowerExecution"
        logger.info(f"Assuming role {audit_role_arn} to update CloudTrail SNS.")
        assumed_role = sts_client.assume_role(
            RoleArn=audit_role_arn,
            RoleSessionName="LaceworkSNSSetup"
        )
        audit_session = boto3.Session(
            aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
            aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
            aws_session_token=assumed_role['Credentials']['SessionToken']
        )
        sns_client = audit_session.client('sns', region_name=region)
        sns_topic_arn = f"arn:aws:sns:{region}:{audit_account_id}:aws-controltower-AllConfigNotifications"
        trail_arn = f"arn:aws:cloudtrail:{region}:{management_account_id}:trail/{trail_name}"
        
        # Get and update sns policy
        attributes = sns_client.get_topic_attributes(
            TopicArn=sns_topic_arn
        )
        policy = json.loads(attributes['Attributes']['Policy'])
        statement_id = "AllowCloudTrailPublish"
        policy_statement = {
            "Sid": statement_id,
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "SNS:Publish",
            "Resource": sns_topic_arn,
            "Condition": {
                "StringEquals": {
                    "AWS:SourceArn": trail_arn
                }
            }
        }
        statements = policy.get('Statement', [])
        statements = [s for s in statements if s.get('Sid') != statement_id]
        statements.append(policy_statement)
        policy['Statement'] = statements
        sns_client.set_topic_attributes(
            TopicArn=sns_topic_arn,
            AttributeName='Policy',
            AttributeValue=json.dumps(policy)
        )
        # Update CloudTrail to use the SNS topic
        ct_client = boto3.client('cloudtrail', region_name=region)
        # The SNS topic typically lives in the Audit Account in CT 4.0
        logger.info(f"Updating CloudTrail {trail_name} to use SNS topic: {sns_topic_arn}")
        ct_client.update_trail(
            Name=trail_name,
            SnsTopicName=sns_topic_arn,
            EnableLogFileValidation=True
        )
        logger.info("Successfully updated CloudTrail SNS.")
        return True
    except Exception as e:
        logger.error(f"Error updating CloudTrail SNS: {str(e)}")
        raise e


def find_config_bucket(audit_session, region):
    """
    Finds the bucket starting with 'aws-controltower-config-logs-' in the Audit account.
    Requires a boto3 session assumed into the Audit Account.
    
    Args:
        audit_session: Boto3 session for the audit account
        region: AWS region
        
    Returns:
        Name of the Config bucket, or raises exception if not found
    """
    logger.info("aws.find_config_bucket called.")
    try:
        s3 = audit_session.client('s3', region_name=region)
        response = s3.list_buckets()
        for bucket in response['Buckets']:
            if bucket['Name'].startswith('aws-controltower-config-logs-'):
                logger.info(f"Found Config Bucket: {bucket['Name']}")
                return bucket['Name']

        raise Exception("Could not find aws-controltower-config-logs bucket in Audit Account.")
    except Exception as e:
        logger.error(f"Error finding Config bucket: {str(e)}")
        raise e