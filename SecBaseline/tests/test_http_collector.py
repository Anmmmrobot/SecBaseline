import unittest
from unittest.mock import MagicMock, patch

from collectors.http import collect_http_data


class TestHttpCollector(unittest.TestCase):
    @patch("collectors.http.requests.get")
    def test_timeout_is_configurable(self, mock_get: MagicMock):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Server": "nginx"}
        mock_get.return_value = mock_response

        collect_http_data("https://example.com", timeout=10.0)
        mock_get.assert_called_once_with("https://example.com", timeout=10.0)


if __name__ == "__main__":
    unittest.main()
