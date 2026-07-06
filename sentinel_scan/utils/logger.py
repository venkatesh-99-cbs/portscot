import logging
import sys

def setup_logging(level=logging.INFO):
    logger = logging.getLogger("SentinelScan")
    logger.setLevel(level)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    return logger

logger = logging.getLogger("SentinelScan")
