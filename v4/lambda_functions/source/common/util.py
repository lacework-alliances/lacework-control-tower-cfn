import logging
import os

from telemetry import send_lacework_telemetry_event

LOGLEVEL = os.environ.get("LOGLEVEL", logging.INFO)
logger = logging.getLogger()
logger.setLevel(LOGLEVEL)


def error_exception(
    msg,
    lacework_token="",
    dataset="",
    build_version="",
    lacework_account_name="",
    function="",
    lacework_sub_account_name="",
):
    logger.error(msg)
    if msg and dataset and build_version and lacework_account_name and lacework_token:
        send_lacework_telemetry_event(
            dataset,
            build_version,
            lacework_account_name,
            '{"error":"' + msg.replace('"', '\\"') + '"}',
            function,
            lacework_token,
            lacework_sub_account_name,
        )
    return Exception(msg)
