import logging
import sys

# Config básica
logger = logging.getLogger("VULNPORTS")
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] (%(name)s) - %(message)s")

handler.setFormatter(formatter)
logger.addHandler(handler)


def get_logger(name: str = None):
    return logger if name is None else logging.getLogger(name)
