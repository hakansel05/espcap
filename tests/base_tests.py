import unittest

from espcap.logger import log, clean_log_file


class BaseTests(unittest.TestCase):
    def __init__(self):
        print('espcap Tests Begins')
        super(BaseTests, self).__init__()


if __name__ == '__main__':
    unittest.main()
