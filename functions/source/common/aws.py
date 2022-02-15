import json
import logging
import os

import boto3
import time

import requests

SUCCESS = "SUCCESS"
FAILED = "FAILED"

STACK_SET_SUCCESS_STATES = ["SUCCEEDED"]
STACK_SET_RUNNING_STATES = ["RUNNING", "STOPPING"]

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


def is_account_in_orgs(acct, orgs):
    logger.info("aws.is_account_in_orgs called.")
    if not orgs:

        return True

    org_client = boto3.client('organizations')
    try:
        response = org_client.list_parents(
            ChildId=acct,
            MaxResults=100
        )
        org_list = [x.strip() for x in orgs.split(',')]
        for parent in response['Parents']:
            for org in org_list:
                if parent["Type"] == "ORGANIZATIONAL_UNIT":
                    org_name = org_client.describe_organizational_unit(
                        OrganizationalUnitId=parent["Id"]
                    )["OrganizationalUnit"]["Name"]
                    if org.lower() == org_name.lower():
                        logger.info("Account {} is in org {}.".format(acct, org))
                        return True
        return False
    except Exception as describe_exception:
        logger.error("Exception getting account org on {} {}.".format(acct, describe_exception))
        return False


def get_org_for_account(acct, orgs):
    logger.info("aws.get_org_for_account called.")
    if not orgs:
        return None

    org_client = boto3.client('organizations')
    try:
        response = org_client.list_parents(
            ChildId=acct,
            MaxResults=100
        )
        org_list = [x.strip() for x in orgs.split(',')]
        for parent in response['Parents']:
            for org in org_list:
                if parent["Type"] == "ORGANIZATIONAL_UNIT":
                    org_name = org_client.describe_organizational_unit(
                        OrganizationalUnitId=parent["Id"]
                    )["OrganizationalUnit"]["Name"]
                    if org.lower() == org_name.lower():
                        return org
        return None
    except Exception as describe_exception:
        logger.error("Exception getting account org on {} {}.".format(acct, describe_exception))
        return None


def wait_for_stack_set_operation(stack_set_name, operation_id):
    logger.info("aws.wait_for_stack_set_operation called.")
    logger.info("Waiting for StackSet Operation {} on StackSet {} to finish".format(operation_id, stack_set_name))
    cloudformation_client = boto3.client("cloudformation")
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


def list_stack_instance_by_account_region(config_stack_set_name, account_id, region):
    logger.info("aws.list_stack_instance_by_account_region called.")
    try:
        cfn_client = boto3.client("cloudformation")
        stack_set_result = cfn_client.list_stack_instances(
            StackSetName=config_stack_set_name,
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
