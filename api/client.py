import requests
from flask import current_app
from http import HTTPStatus

from .errors import (CTRInvalidJWTError,
                     CTRBadRequestError,
                     CTRUnexpectedResponseError,
                     CTRInternalServerError,
                     CTRTooManyRequestsError,
                     CTRSSLError, AuthorizationError)


class Client:
    def __init__(self, credentials):
        self.session = None
        self.credentials = credentials
        self.base_url = current_app.config['API_URL']

    def open_session(self):
        self.session = requests.Session()

    def close_session(self):
        self.session.close()

    def format_url(self, entity, value, path=None):
        url = self.base_url.format(entity=entity, value=value)
        if path:
            url = url + path
        return url

    def call_api(self, url, method='GET', params=None, data=None):
        error = None
        result = None

        if not self.session.headers.get('Authorization'):
            self._auth()

        try:
            if method == 'POST':
                response = self.session.post(url, params=params, data=data)
            elif method == 'DELETE':
                response = self.session.delete(url)
            else:
                response = self.session.get(url, params=params)
        except requests.exceptions.SSLError as ex:
            raise CTRSSLError(ex)

        if response.ok:
            if response.status_code == HTTPStatus.OK:
                result = response.json()
        else:
            if response.status_code == HTTPStatus.UNAUTHORIZED:
                raise AuthorizationError(str(response.json()['error']))
            elif response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                raise CTRTooManyRequestsError(response)
            elif response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR:
                raise CTRInternalServerError
            else:
                error = str(response.json()['error'])
        return result, error

    def _set_headers(self, response):
        token = response.json().get('access_token')
        token_type = response.json().get('token_type', 'Bearer')
        if not token:
            raise CTRBadRequestError('Access Token does not exist.')

        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': f'{token_type} {token}'
        }
        headers.update(current_app.config['CTR_HEADERS'])

        self.session.headers.update(**headers)

    def _auth(self):

        body = {
            'resource': current_app.config['API_HOST'],
            'client_id': self.credentials['client_id'],
            'client_secret': self.credentials['client_secret'],
            'grant_type': 'client_credentials'
        }

        url = current_app.config['AUTH_URL'].format(
            tenant_id=self.credentials['tenant_id']
        )
        response = self.session.get(
            url,
            data=body,
            headers=current_app.config['CTR_HEADERS'])

        if response.ok:
            self._set_headers(response)
            return

        elif response.status_code in (HTTPStatus.UNAUTHORIZED,
                                      HTTPStatus.BAD_REQUEST):
            raise AuthorizationError(
                str(response.json().get(
                    'error_description',
                    'on Microsoft Defender ATP side'
                ))
            )
        elif response.status_code == HTTPStatus.NOT_FOUND:
            raise CTRInvalidJWTError()
        raise CTRUnexpectedResponseError(response.json())
