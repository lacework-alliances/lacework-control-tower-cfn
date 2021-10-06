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
import boto3, json, time, os, logging, botocore, uuid
from crhelper import CfnResource
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
session = boto3.Session()

helper = CfnResource(json_logging=False, log_level='INFO', boto_level='CRITICAL', sleep_on_delete=15)

@helper.create # crhelper methods to create the stack set if needed and create stack instances
@helper.update
def create(event, context):
    logger.info('setup.create called.')
    logger.info(json.dumps(event))
    try:
        firstLaunch = False
        stackSetName = os.environ['stackSetName']
        stackSetUrl = os.environ['stackSetUrl']
        laceworkAcctName = os.environ['laceworkAcctName']
        laceworkSecret = os.environ['laceworkSecret']
        laceworkStackSNS = os.environ['laceworkStackSNS']
        managementAccountId = context.invoked_function_arn.split(":")[4]
        cloudFormationClient = session.client('cloudformation')
        regionName = context.invoked_function_arn.split(":")[3]
        cloudFormationClient.describe_stack_set(StackSetName=stackSetName)
        logger.info('Stack set {} already exist'.format(stackSetName))
        helper.Data.update({"result": stackSetName})
        
    except Exception as describeException:
        logger.info('Stack set {} does not exist, creating it now.'.format(stackSetName))
        cloudFormationClient.create_stack_set(
            StackSetName=stackSetName,
            Description='Configures Lacework to monitor your AWS accounts. Launch as Stack Set in your Control Tower landing zone management account.',
            TemplateURL=stackSetUrl,
            Parameters=[
                {
                    'ParameterKey': 'LaceworkAccountNumber',
                    'ParameterValue': laceworkAccId,
                    'UsePreviousValue': False,
                    'ResolvedValue': 'string'
                }
            ],
            Capabilities=[
                'CAPABILITY_NAMED_IAM'
            ],
            AdministrationRoleARN='arn:aws:iam::' + managementAccountId + ':role/service-role/AWSControlTowerStackSetRole',
            ExecutionRoleName='AWSControlTowerExecution')
            
        try:
            result = cloudFormationClient.describe_stack_set(StackSetName=stackSetName)
            firstLaunch = True
            logger.info('StackSet {} deployed'.format(stackSetName))
        except cloudFormationClient.exceptions.StackSetNotFoundException as describeException:
            logger.error('Exception getting new stack set, {}'.format(describeException))
            raise describeException
        
        try:
            if firstLaunch and len(os.environ['seedAccounts']) > 0 :
                logger.info("New accounts : {}".format(os.environ['seedAccounts']))
                accountList = os.environ['seedAccounts'].split(",")
                snsClient = session.client('sns')
                messageBody = {}
                messageBody[stackSetName] = { 'target_accounts': accountList, 'target_regions': [regionName] }
                try:
                    snsResponse = snsClient.publish(
                        TopicArn=laceworkStackSNS,
                        Message = json.dumps(messageBody))
                    
                    logger.info("Queued for stackset instance creation: {}".format(snsResponse))
                except Exception as snsException:
                    logger.error("Failed to send queue for stackset instance creation: {}".format(snsException))
            else:
                logger.info("No additional stackset instances requested")
        except Exception as create_exception:
            logger.error('Exception creating stack instance with {}'.format(create_exception))
            raise create_exception
        
        helper.Data.update({"result": stackSetName})

    if not helper.Data.get("result"):
        raise ValueError("Error occurred during solution setup")
    
    return None

@helper.delete # crhelper method to delete stack set and stack instances
def delete(event, context):
    logger.info('setup.delete called.')
    deleteWaitTime = (int(context.get_remaining_time_in_millis()) - 100)/1000
    deleteSleepTime = 30
    try:
        stackSetName = os.environ['stackSetName']
        stackSetUrl = os.environ['stackSetUrl']
        managementAccountId = context.invoked_function_arn.split(":")[4]
        cloudFormationClient = session.client('cloudformation')
        regionName = context.invoked_function_arn.split(":")[3]
        cloudFormationClient.describe_stack_set(StackSetName=stackSetName)
        logger.info('Stack set {} exist'.format(stackSetName))

        paginator = cloudFormationClient.get_paginator('list_stack_instances')
        pageIterator = paginator.paginate(StackSetName= stackSetName)
        stackSetList = []
        accountList = []
        regionList = []
        for page in pageIterator:
            if 'Summaries' in page:
                stackSetList.extend(page['Summaries'])
        for instance in stackSetList:
            accountList.append(instance['Account'])
            regionList.append(instance['Region'])
        regionList = list(set(regionList))
        accountList = list(set(accountList))
        logger.info("StackSet instances found in region(s): {}".format(regionList))
        logger.info("StackSet instances found in account(s): {}".format(accountList))
        
        try:
            if len(accountList) > 0:
                response = cloudFormationClient.delete_stack_instances(
                    StackSetName=stackSetName,
                    Accounts=accountList,
                    Regions=regionList,
                    RetainStacks=False)
                logger.info(response)
                
                status = cloudFormationClient.describe_stack_set_operation(
                    StackSetName=stackSetName,
                    OperationId=response['OperationId'])
                    
                while status['StackSetOperation']['Status'] == 'RUNNING' and deleteWaitTime>0:
                    time.sleep(deleteSleepTime)
                    deleteWaitTime=deleteWaitTime-deleteSleepTime
                    status = cloudFormationClient.describe_stack_set_operation(
                        StackSetName=stackSetName,
                        OperationId=response['OperationId'])
                    logger.info("StackSet instance delete status {}".format(status))
            
            try:
                response = cloudFormationClient.delete_stack_set(StackSetName=stackSetName)
                logger.info("StackSet template delete status {}".format(response))
            except Exception as stackSetException:
                logger.warning("Problem occurred while deleting, StackSet still exist : {}".format(stackSetException))
                
        except Exception as describeException:
            logger.error(describeException)

    except Exception as describeException:
        logger.error(describeException)
        return None
    
    return None
def lambda_handler(event, context):
    logger.info('setup.lambda_handler called.')
    logger.info(json.dumps(event))
    try:
        if 'RequestType' in event: helper(event, context)
    except Exception as e:
        helper.init_failure(e)