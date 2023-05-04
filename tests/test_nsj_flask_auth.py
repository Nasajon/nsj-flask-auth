from typing import Dict
import unittest
import requests


class TestNsjFlaskAuth(unittest.TestCase):

    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)
        self.url_base: str
        self.access_token: str
        self.base_params: Dict
        self.base_headers: Dict

    @classmethod
    def setUpClass(self):
        self.url_base = "http://localhost:5000"
        self.access_token = self.get_access_token()
        self.base_params = {
            "tenant": 47,
            "grupo_empresarial": "95cd450c-30c5-4172-af2b-cdece39073bf",
            "empresa": "431bc005-9894-4c86-9dcd-7d1da9e2d006",
            "estabelecimento": "39836516-7240-4fe5-847b-d5ee0f57252d"
        }
        self.base_headers = {
            "Authorization": self.access_token
        }

    @classmethod
    def get_access_token(self, email='wallacepinho@nasajon.com.br', password='123456'):
        url = 'https://auth.dev.nasajonsistemas.com.br/auth/realms/DEV/protocol/openid-connect/token'
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        body = {
            "client_id": "erp_api",
            "username": email,
            "password": password,
            "grant_type": "password",
            "scope": "offline_access"
        }
        response = requests.post(url=url, headers=headers, data=body)
        return response.json()["access_token"]

    def test_aaaaa(self):
        response = requests.get(self.url_base + "/ping/")
        self.assertEqual(response.status_code, 200)

    def test_escopo_estabelecimento(self):
        response = requests.get(self.url_base + "/escopo-estabelecimento/",
                                params=self.base_params, headers=self.base_headers)
        self.assertEqual(response.status_code, 200)

    def test_escopo_empresa(self):
        response = requests.get(self.url_base + "/escopo-empresa/",
                                params=self.base_params, headers=self.base_headers)
        self.assertEqual(response.status_code, 200)

    def test_escopo_grupo_empresarial(self):
        response = requests.get(self.url_base + "/escopo-grupo-empresarial/",
                                params=self.base_params, headers=self.base_headers)
        self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()
