import json
from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify
from http import HTTPStatus

from .errors import (CTRBadRequestError, CTRNotFoundError,
                     CTRUnexpectedResponseError, CTRInvalidCredentialsError)


def get_jwt():
    """
    Parse the incoming request's Authorization Bearer JWT for some credentials.
    Validate its signature against the application's secret key.

    Note. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return jwt.decode(token, current_app.config['SECRET_KEY'])
    except (KeyError, ValueError, AssertionError, JoseError):
        return {}


def get_json(schema):
    """
    Parse the incoming request's data as JSON.
    Validate it against the specified schema.

    Note. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    data = request.get_json(force=True, silent=True, cache=False)

    error = schema.validate(data) or None

    if error:
        data = None
        error = {
            'code': 'invalid_payload',
            'message': f'Invalid JSON payload received. {json.dumps(error)}.',
        }

    return data, error


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(error):
    # According to the official documentation, an error here means that the
    # corresponding TR module is in an incorrect state and needs to be
    # reconfigured:
    # https://visibility.amp.cisco.com/help/alerts-errors-warnings.
    error['type'] = 'fatal'
    error['code'] = error.pop('code').lower().replace('_', ' ')

    return jsonify({'errors': [error]})


def get_token(session, credentials):
    body = {
        'resource': current_app.config['API_HOST'],
        'client_id': credentials['client_id'],
        'client_secret': credentials['client_secret'],
        'grant_type': 'client_credentials'
    }

    url = current_app.config['AUTH_URL'].format(
        tenant_id=credentials['tenant_id']
    )

    response = session.get(url, data=body)
    if response.ok:
        token = response.json().get('access_token')
        token_type = response.json().get('token_type', 'Bearer')
        if not token:
            raise CTRBadRequestError('Access Token does not exist.')

        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': ('Cisco Threat Response Integrations '
                           '<tr-integrations-support@cisco.com>'),
            'Authorization': f'{token_type} {token}'
        }

        session.headers.update(**headers)
        return session

    elif response.status_code == HTTPStatus.BAD_REQUEST:
        if response.json().get('error') in (
                'unauthorized_client', 'invalid_request'):
            raise CTRInvalidCredentialsError()
    raise CTRUnexpectedResponseError(response.json())


def call_api(session, url, credentials):
    if not session.headers:
        session = get_token(session, credentials)

    def _call():
        return session.get(url)

    response = _call()
    if response.status_code == HTTPStatus.UNAUTHORIZED:
        session = get_token(session, credentials)
        response = _call()

    if not response.ok:
        if response.status_code == HTTPStatus.BAD_REQUEST:
            raise CTRBadRequestError(
                f"{response.json()['error']['message']}"
            )
        if response.status_code == HTTPStatus.NOT_FOUND:
            raise CTRNotFoundError()

        if response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR:
            raise CTRUnexpectedResponseError(response.json())

    return response.json()
