import logging
import urllib2
import xml.etree.ElementTree as ET

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from rest_framework import status
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from seahub.api2.models import TokenV2
from seahub.api2.utils import api_error
from seahub.utils.ip import get_remote_ip

# Get an instance of a logger
logger = logging.getLogger(__name__)

class ObtainPASSOToken(APIView):
    throttle_classes = (AnonRateThrottle, )

    def get_pa_sso_addr(self):
        if settings.PA_SSO_ADDR:
            return '%s?parameter=' % settings.PA_SSO_ADDR
        else:
            raise ImproperlyConfigured("No PA_SSO_ADDR found in settings.")

    def build_xml_query_string(self, pa_session):
        if not settings.PA_SSO_SERVICE_ID:
            raise ImproperlyConfigured("No PA_SSO_SERVICE_ID found in settings.")

        if not settings.PA_SSO_HOSTNAME:
            raise ImproperlyConfigured("No PA_SSO_HOSTNAME found in settings.")

        if not settings.PA_SSO_REGISTERED_INFO:
            raise ImproperlyConfigured("No PA_SSO_REGISTERED_INFO found in settings.")

        s = '''<?xml version="1.0" encoding="UTF-8" standalone="no"?><request><action>validate</action><serviceid>%s</serviceid><token>%s</token><hostname>%s</hostname><registeredinfo>%s</registeredinfo></request>''' % (
            settings.PA_SSO_SERVICE_ID, 'PASESSION:' + pa_session,
            settings.PA_SSO_HOSTNAME, settings.PA_SSO_REGISTERED_INFO)
        return s

    def fetch_sso_service_content(self, pa_sso_addr):
        try:
            resp = urllib2.urlopen(pa_sso_addr)
            content = resp.read()
        except urllib2.HTTPError as e:
            logger.error(e)
            raise
        except urllib2.URLError as e:
            logger.error(e)
            raise

        return content

    def fetch_um_id_from_sso(self, pa_sso_addr):
        content = self.fetch_sso_service_content(pa_sso_addr)

        uid = None
        root = ET.fromstring(content)
        for child in root:
            if child.tag == 'uid':
                uid = child.text

        return uid

    def post(self, request):
        # 1. get PASESSION from request post
        pa_session = request.POST.get('PASESSION', '')
        if not pa_session:
            return api_error(status.HTTP_400_BAD_REQUEST, 'Failed to get PASESSION from request post')

        # 2. send PASESSION to SSO service to get UM account
        pa_sso_addr = self.get_pa_sso_addr().rstrip('/') + self.build_xml_query_string(pa_session)

        try:
            uid = self.fetch_um_id_from_sso(pa_sso_addr)
        except urllib2.HTTPError as e:
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Failed to reach sso service')
        except urllib2.URLError as e:
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Failed to reach sso service')

        if not uid:
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, 'Failed to get uid from sso response')

        # 3. construct uid to username
        if not settings.PA_SSO_USERNAME_SUFFIX or \
           not settings.PA_SSO_USERNAME_SUFFIX.startswith('@'):
            return api_error(status.HTTP_500_INTERNAL_SERVER_ERROR, '`PA_SSO_USERNAME_SUFFIX` is not set in seahub_settings.py or not starts with "@", please contact system admin.')

        username = uid.lower() + settings.PA_SSO_USERNAME_SUFFIX

        # 4. generate api token for the user
        platform = request.POST.get('platform', '')
        device_id = request.POST.get('device_id', '')
        device_name = request.POST.get('device_name', '')
        client_version = request.POST.get('client_version', '')
        platform_version = request.POST.get('platform_version', '')
        login_ip = get_remote_ip(request)

        if not platform:
            return api_error(status.HTTP_400_BAD_REQUEST, 'No platform in post data')

        if not device_id:
            return api_error(status.HTTP_400_BAD_REQUEST, 'No device_id in post data')

        # remove old token
        TokenV2.objects.filter(user=username, platform=platform, device_id=device_id).delete()

        t = TokenV2(user=username, platform=platform, device_id=device_id,
                    device_name=device_name, client_version=client_version,
                    platform_version=platform_version, last_login_ip=login_ip)
        t.save()

        return Response({'token': t.key})
