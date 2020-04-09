import os

from version import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    AUTH_URL = "https://login.windows.net/{tenant_id}/oauth2/token"

    API_URL = 'https://api.securitycenter.windows.com'
