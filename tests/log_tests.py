from espcap.logger import log, clean_log_file
from tests.base_tests import BaseTests


class LogTests(BaseTests):

    @staticmethod
    def test_log():
        clean_log_file()
        log('Test Trivial')
        clean_log_file()
