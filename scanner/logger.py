import logging
from pathlib import Path

LOG_PATH = Path(__file__).resolve().parent / 'scanner.log'

logger = logging.getLogger('scanner')
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.FileHandler(LOG_PATH)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
