import logging
import os

LOGLEVEL = os.environ.get('LOGLEVEL', logging.INFO)
logger = logging.getLogger()
logger.setLevel(LOGLEVEL)

def error_exception(msg):
    logger.error(msg)
    return Exception(msg)
