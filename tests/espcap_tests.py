from click.testing import CliRunner

from src.espcap import main
from tests.base_tests import BaseTests


class EspcapTests(BaseTests):
    runner = CliRunner()
    runner.invoke(main, ['--node', '127.0.0.1:9200', '--file',
                         '../test_pcaps/test_http.pcap', '--chunk', 10000])
