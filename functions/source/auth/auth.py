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

def message_processing(messages):
    logger.info("auth.message_processing called.")
    target_stackset = {}
    for message in messages:
        payload = json.loads(message["Sns"]["Message"])
        access_token_check(payload)

def access_token_check(messages):
    logger.info("auth.access_token_check called.")
    sqsClient = session.client("sqs")
    snsClient = session.client("sns")
    laceworkAuthSNS = os.environ["laceworkAuthSNS"]
    laceworkDLQ = os.environ["laceworkDLQ"]
    laceworkApiCredentials = os.environ["laceworkApiCredentials"]
    laceworkAccName = os.environ["laceworkAcctName"]


def lambda_handler(event, context):
    logger.info("auth.lambda_handler called.")
    logger.info(json.dumps(event))
    try:
        if "Records" in event:
            message_processing(event["Records"])
    except Exception as e:
        logger.error(e)