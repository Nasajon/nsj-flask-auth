from nsj_flask_auth import __version__, Auth
import unittest
import requests

auth = Auth()

class TestNsjFlaskAuth(unittest.TestCase):

    def setUpClass(self):
        self.url_base = "localhost:5000"
        self.auth = auth

    def test_aaaaa(self):
        response = requests.get(self.url_base + "/ping/")
        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()