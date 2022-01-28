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
from datetime import datetime, timedelta, timezone

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
        auth_sns_processing()
    except Exception as e:
        logger.error(e)


def auth_sns_processing():
    logger.info("auth.auth_sns_processing called.")
    refresh_access_token()


def refresh_access_token():
    logger.info("auth.refresh_access_token called.")
    lacework_api_credentials = os.environ['lacework_api_credentials']
    lacework_url = os.environ['lacework_url']

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
        logger.info("Token expiration is {}".format(token_expiry))
        expiration = datetime.fromisoformat(token_expiry.replace("Z", "+00:00"))

        logger.info("Formatted ISO token expiration is {}".format(expiration))
        early_refresh_time = expiration - timedelta(hours=6)
        now_time = datetime.now(timezone.utc)
        logger.info("Now is {} and early refresh time is {}".format(now_time, early_refresh_time))
        if now_time < early_refresh_time:
            logger.info("Access token is still valid {}".format(expiration))
            return None

        logger.info("Access token will expire soon. Refreshing... {}".format(token_expiry))

        response = send_lacework_api_access_token_request(lacework_url, access_key_id, secret_key)
        logger.info('API response code : {}'.format(response.status_code))
        logger.debug('API response : {}'.format(response.text))
        if response.status_code == 201:
            payload_response = response.json()
            expires_at = payload_response['expiresAt']
            token = payload_response['token']
            secret_string_dict['AccessToken'] = token
            secret_string_dict['TokenExpiry'] = expires_at
            logger.info("New token expiration is {}".format(expires_at))
            secret_client.update_secret(SecretId=lacework_api_credentials, SecretString=json.dumps(secret_string_dict))
            return token
        else:
            logger.error("Generate access key failure {} {}".format(response.status_code, response.text))
            return None
    except Exception as e:
        logger.error("Error setting up initial access token {}".format(e))
        return None


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
