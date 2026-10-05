import socket
import unittest

class TestFDSet(unittest.TestCase):
    def test_mock_server_transport(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        # Mock exfiltration listener test
        port = s.getsockname()[1]
        self.assertTrue(port > 0)
        s.close()
