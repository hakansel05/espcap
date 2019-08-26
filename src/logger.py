import datetime
from pathlib import Path

LOG_FILE = '../logs/packet-errors.log'

LOG_FILE_NAME = Path(LOG_FILE)
LOG_FILE_NAME.touch(exist_ok=True)


def log(message: str):
    f = open(LOG_FILE_NAME, 'a+')
    f.write('\r\n[ERROR]:\t[{}]\t{}'.format(datetime.datetime.now(), message))
    f.close()


def clean_log_file():
    f = open(LOG_FILE_NAME, 'r+')
    f.truncate(0)
    f.close()
