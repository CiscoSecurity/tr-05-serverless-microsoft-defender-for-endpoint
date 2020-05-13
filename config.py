import os

from version import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    AUTH_URL = "https://login.windows.net/{tenant_id}/oauth2/token"

    API_HOST = 'https://api.securitycenter.windows.com'
    API_URL = API_HOST + '/api/v1.0/{entity}/{value}'

    MD_ATP_OBSERVABLE_TYPES = (
        'sha1', 'sha256', 'ip', 'domain'
    )

    CTIM_SCHEMA_VERSION = '1.0.16'

    CTR_DEFAULT_ENTITIES_LIMIT = 100
    CTR_ENTITIES_LIMIT = CTR_DEFAULT_ENTITIES_LIMIT

    try:
        limit = int(os.environ.get('CTR_ENTITIES_LIMIT'))
        if limit > 0:
            CTR_ENTITIES_LIMIT = limit
    except (ValueError, TypeError):
        pass
