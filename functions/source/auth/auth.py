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
import datetime
from datetime import datetime

import boto3
import json
import logging
import os
import requests

LOGLEVEL = os.environ.get('LOGLEVEL', logging.INFO)
logger = logging.getLogger()
logger.setLevel(LOGLEVEL)
logging.getLogger("boto3").setLevel(logging.CRITICAL)
logging.getLogger("botocore").setLevel(logging.CRITICAL)
session = boto3.Session()


def lambda_handler(event, context):
    logger.info("auth.lambda_handler called.")
    logger.info(json.dumps(event))
    try:
        # called from stack_setSNS
        if 'Records' in event:
            auth_sns_processing(event['Records'])
        else:
            logger.info("Event not processed.")
    except Exception as e:
        logger.error(e)


def auth_sns_processing(messages):
    logger.info("auth.auth_sns_processing called.")
    refresh_access_token(messages)

def refresh_access_token(messages):
    logger.info("auth.refresh_access_token called.")
    lacework_api_credentials = os.environ['lacework_api_credentials']
    lacework_account_name = os.environ['lacework_account_name']

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
        token_expiry = secret_string_dict['TokenExpiry']  # yyyy-MM-ddTHH:mm:ss.SSSZ

        datetime_obj = datetime.strptime(token_expiry, '%Y-%m-%dT%H:%M:%S.%fZ')

        if datetime_obj - datetime.timedelta(hours=12) < datetime.utcnow():
            logger.info("Access token is still valid {}".format(token_expiry))
            return None

        logger.info("Access token is expires soon. Refreshing... {}".format(token_expiry))

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
            return token
        else:
            logger.error("Generate access key failure {} {}".format(response.status_code, response.text))
            return None
    except Exception as e:
        logger.error("Error setting up initial access token {}".format(e))
        return None
