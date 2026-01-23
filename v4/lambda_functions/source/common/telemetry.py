import logging
import os
import json

import requests


LOGLEVEL = os.environ.get("LOGLEVEL", logging.INFO)

logger = logging.getLogger()
logger.setLevel(LOGLEVEL)


def send_lacework_telemetry_event(
    dataset,
    version,
    account,
    event,
    function=None,
    token=None,
    subaccount="000000",
    eventdata="{}",
):
    logger.info("Call to send events.")
    try:
        payload = {
            "account": str(account),
            "sub-account": str(subaccount),
            "tech-partner": "AWS",
            "integration-name": "aws-control-tower-lacework",
            "version": str(version),
            "service": "AWS CloudFormation",
            "install-method": "cloudformation",
            "function": function if function else "unknown",
            "event": str(event),
            "event-data": eventdata,
            "sample_rate_100": True,
            "telemetry_source": "external",
            "telemetry_type": "customer",
        }
        logger.info("Generate payload : {}".format(payload))
        base_url = f"https://{account}.lacework.net/api/v2/telemetry/OtelMetrics"
        # the try should be here, if we can't get the token then log locally

        resp = requests.post(
            base_url,
            headers={"Authorization": token, "Content-Type": "application/json"},
            verify=True,
            data=json.dumps(payload),
            params={"dataset": dataset},
        )
        logger.info("Telemetry response {} {}".format(resp, resp.content))

    except Exception as e:
        logger.warning("Error sending to Telemetry: {}.".format(e))
