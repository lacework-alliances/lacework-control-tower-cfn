import logging
import os

from honeycomb import send_honeycomb_event

LOGLEVEL = os.environ.get('LOGLEVEL', logging.INFO)
logger = logging.getLogger()
logger.setLevel(LOGLEVEL)


def error_exception(msg, honey_api_key="", dataset="", build_version="", lacework_account_name="",
                    lacework_sub_account_name=""):
    logger.error(msg)
    if honey_api_key and dataset and build_version and lacework_account_name and lacework_sub_account_name:
        send_honeycomb_event(honey_api_key, dataset, build_version, lacework_account_name, "ERROR",
                             lacework_sub_account_name, '{"error":"' + msg + '"')
    return Exception(msg)
