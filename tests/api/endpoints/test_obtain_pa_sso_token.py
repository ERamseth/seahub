from urllib2 import HTTPError, URLError
import json
from mock import patch
import xml.etree.ElementTree as ET

from seahub.test_utils import BaseTestCase
from seahub.api2.models import TokenV2
from seahub.api2.endpoints.obtain_pa_sso_token import ObtainPASSOToken

class ObtainPASSOTokenTest(BaseTestCase):
    def setUp(self):
        self.token_url = '/passo/auth-token/'
        self.sso_resp = '''<response>
<returncode>200</returncode>
<uid>RUANXIAOFENG685</uid>
<token>PASESSION:4feR4F!GjdUhh34hvJwnkvF5Id9RDEkAQHr7aYiriGPollqz!FrPYAVzbXGaTDm0aITmEK9frbqlmOGODNhMfCGamnaSTB6ny-KZUg8KVjAjQL-gvRuzg4CX6kUSua54QhTlKw6PnE0PG3NV6fk5Pw==|NjAxNT0COOyy0CAxOSowMjozMw==</token>
</response> '''

        self.invalid_sso_resp = '''<response>
        <returncode>validatepatoken-failed</returncode>
</response>'''

    @patch.object(ObtainPASSOToken, 'fetch_sso_service_content')
    def test_post(self, mock_fetch_sso_service_content):
        mock_fetch_sso_service_content.return_value = self.sso_resp

        resp = self.client.post('/passo/auth-token/', {
            "platform": "ios",
            "device_id": "xxx",
            "PASESSION": "guc8s94vra9ngp3k0klbwgnt7azh4359"
        }, **{'HTTP_USER_AGENT': 'KuaiLePingAn-YunPan'
          }
        )

        self.assertEqual(200, resp.status_code)

        assert len(TokenV2.objects.all()) == 1
        t = TokenV2.objects.all()[0]
        json_resp = json.loads(resp.content)
        assert json_resp['token'] == t.key
        assert t.user == 'RUANXIAOFENG685@pingan.com.cn'.lower()

        # token should not be reusable
        resp = self.client.post('/passo/auth-token/', {
            "platform": "ios",
            "device_id": "xxx",
            "PASESSION": "guc8s94vra9ngp3k0klbwgnt7azh4359"
        }, **{'HTTP_USER_AGENT': 'KuaiLePingAn-YunPan',
          }
        )
        assert len(TokenV2.objects.all()) == 1
        json_resp = json.loads(resp.content)
        assert json_resp['token'] != t.key

    @patch.object(ObtainPASSOToken, 'fetch_sso_service_content')
    def test_post_when_sso_content_is_invalid(self, mock_fetch_sso_service_content):
        mock_fetch_sso_service_content.return_value = self.invalid_sso_resp

        resp = self.client.post('/passo/auth-token/', {
            "PASESSION": "guc8s94vra9ngp3k0klbwgnt7azh4359"
        }, **{'HTTP_USER_AGENT': 'KuaiLePingAn-YunPan',
          }
        )

        self.assertEqual(500, resp.status_code)
        assert "Failed to get uid from sso response" in resp.content

    @patch('seahub.api2.endpoints.obtain_pa_sso_token.urllib2.urlopen')
    def test_post_when_http_error_raise(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError('', 404, 'not found', None, None)

        resp = self.client.post('/passo/auth-token/', {
            "PASESSION": "guc8s94vra9ngp3k0klbwgnt7azh4359"
        }, **{'HTTP_USER_AGENT': 'KuaiLePingAn-YunPan',
          }
        )

        self.assertEqual(500, resp.status_code)
        assert "Failed to reach sso service" in resp.content

    @patch('seahub.api2.endpoints.obtain_pa_sso_token.urllib2.urlopen')
    def test_post_when_url_error_raise(self, mock_urlopen):
        mock_urlopen.side_effect = URLError('no host given')

        resp = self.client.post('/passo/auth-token/', {
            "PASESSION": "guc8s94vra9ngp3k0klbwgnt7azh4359"
        }, **{'HTTP_USER_AGENT': 'KuaiLePingAn-YunPan',
          }
        )

        self.assertEqual(500, resp.status_code)
        assert "Failed to reach sso service" in resp.content

    def test_build_xml_query_string(self):
        s = ObtainPASSOToken().build_xml_query_string('abc')

        root = ET.fromstring(s)
        for child in root:
            if child.tag == 'token':
                assert child.text == 'PASESSION:abc'

    @patch.object(ObtainPASSOToken, 'fetch_sso_service_content')
    def test_fetch_um_id_from_sso(self, mock_fetch_sso_service_content):
        mock_fetch_sso_service_content.return_value = self.sso_resp

        assert ObtainPASSOToken().fetch_um_id_from_sso('') == 'RUANXIAOFENG685'

    @patch.object(ObtainPASSOToken, 'fetch_sso_service_content')
    def test_fetch_um_id_from_sso_when_content_is_invalid(
            self, mock_fetch_sso_service_content):
        mock_fetch_sso_service_content.return_value = self.invalid_sso_resp

        assert ObtainPASSOToken().fetch_um_id_from_sso('') is None
