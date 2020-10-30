import os

from version import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY')

    AUTH_URL = "https://login.windows.net/{tenant_id}/oauth2/token"

    API_HOST = 'https://api.securitycenter.windows.com'
    API_VERSION = 'v1.0'
    BASE_URL = f'{API_HOST}/api/{API_VERSION}'
    API_URL = BASE_URL + '/{entity}/{value}'
    ADVANCED_HUNTING_URL = f'{BASE_URL}/advancedqueries/run'
    INDICATOR_URL = f'{BASE_URL}/indicators'
    SECURITY_CENTER_URL = 'https://securitycenter.windows.com'

    MD_ATP_OBSERVABLE_TYPES = {
        'sha1': 'SHA1',
        'sha256': 'SHA256',
        'md5': 'MD5',
        'ip': 'IP',
        'ipv6': 'IPV6',
        'domain': 'Domain',
        'ms_machine_id': 'ms_machine_id'
    }

    CTIM_SCHEMA_VERSION = '1.0.17'

    CTR_HEADERS = {
        'User-Agent': 'Cisco-CiscoThreatResponseMicrosoftDefenderATP/1.0.0'
    }

    CTR_DEFAULT_ENTITIES_LIMIT = 100
    CTR_ENTITIES_LIMIT = CTR_DEFAULT_ENTITIES_LIMIT

    try:
        limit = int(os.environ.get('CTR_ENTITIES_LIMIT'))
        if limit > 0:
            CTR_ENTITIES_LIMIT = limit
    except (ValueError, TypeError):
        pass
