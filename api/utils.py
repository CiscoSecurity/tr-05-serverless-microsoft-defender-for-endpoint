import os
import requests
from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify
from werkzeug.exceptions import Forbidden, BadRequest
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
        raise Forbidden('Invalid Authorization Bearer JWT.')


def get_json(schema):
    """
    Parse the incoming request's data as JSON.
    Validate it against the specified schema.

    Note. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    data = request.get_json(force=True, silent=True, cache=False)

    message = schema.validate(data)

    if message:
        raise BadRequest(message)

    return data


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(error):
    return jsonify({'errors': [error]})


def get_token(credentials):
    body = {
        'resource': current_app.config['API_URL'],
        'client_id': credentials['client_id'],
        'client_secret': credentials['client_secret'],
        'grant_type': 'client_credentials'
    }

    url = current_app.config['AUTH_URL'].format(
        tenant_id=credentials['tenant_id']
    )

    response = requests.get(url, data=body)
    if response.ok:
        token = response.json().get('access_token')
        token_type = response.json().get('token_type', 'Bearer')
        if not token:
            raise CTRBadRequestError('Access Token does not exist.')

        token = f"{token_type} {token}"
        os.environ['TOKEN'] = token
        return token

    if response.status_code == HTTPStatus.BAD_REQUEST:
        if response.json().get('error') in (
                'unauthorized_client', 'invalid_request'):
            raise CTRInvalidCredentialsError()
    raise CTRUnexpectedResponseError(response.json())


def call_api(url, credentials):
    token = os.environ.get('TOKEN')
    if not token:
        token = get_token(credentials)
        os.environ['TOKEN'] = token

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': ('Cisco Threat Response Integrations '
                       '<tr-integrations-support@cisco.com>'),
        'Authorization': token
    }

    def _call():
        return requests.get(url, headers=headers)

    response = _call()
    if response.status_code == HTTPStatus.UNAUTHORIZED:
        token = get_token(credentials)
        os.environ['TOKEN'] = token
        response = _call()

    if not response.ok:
        if response.status_code == HTTPStatus.NOT_FOUND:
            raise CTRNotFoundError()

        if response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR:
            raise CTRUnexpectedResponseError(response.json())

    return response.json()
