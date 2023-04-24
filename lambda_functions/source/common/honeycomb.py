import logging
import os

import requests

LOGLEVEL = os.environ.get('LOGLEVEL', logging.INFO)
logger = logging.getLogger()
logger.setLevel(LOGLEVEL)


def send_honeycomb_event(honey_key, dataset, version, account, event, subaccount="000000", eventdata="{}"):
    logger.info("honeycomb.send_honeycomb_event called.")

    try:
        payload = '''
        {{
            "account": "{}",
            "sub-account": "{}",
            "tech-partner": "AWS",
            "integration-name": "lacework-aws-control-tower-cloudformation",
            "version": "{}",
            "service": "AWS Control Tower",
            "install-method": "cloudformation",
            "function": "account.py",
            "event": "{}",
            "event-data": {}
        }}
        '''.format(account, subaccount, version, event, eventdata)
        logger.info('Generate payload : {}'.format(payload))
        resp = requests.post("https://api.honeycomb.io/1/events/" + dataset,
                         headers={'X-Honeycomb-Team': honey_key,
                                  'content-type': 'application/json'},
                         verify=True, data=payload)
        logger.info("Honeycomb response {} {}".format(resp, resp.content))

    except Exception as e:
        logger.warning("Get error sending to Honeycomb: {}.".format(e))
