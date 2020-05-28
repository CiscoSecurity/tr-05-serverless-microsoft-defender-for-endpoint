import json
from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify, g
from http import HTTPStatus

from .errors import (CTRInvalidCredentialsError,
                     CTRInvalidJWTError,
                     CTRBadRequestError,
                     CTRUnexpectedResponseError,
                     CTRInternalServerError,
                     CTRTooManyRequestsError)


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
            'code': 'invalid payload',
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

    data = {'errors': [error]}

    if g.get('sightings') and g.sightings:
        data['data'] = {'sightings': g.sightings}

    return jsonify(data)


def set_headers(session):
    credentials = get_jwt()

    body = {
        'resource': current_app.config['API_HOST'],
        'client_id': credentials.get('client_id', ''),
        'client_secret': credentials.get('client_secret', ''),
        'grant_type': 'client_credentials'
    }

    url = current_app.config['AUTH_URL'].format(
        tenant_id=credentials.get('tenant_id', '')
    )

    response = session.get(url,
                           data=body,
                           headers=current_app.config['CTR_HEADERS'])
    if response.ok:
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

        session.headers.update(**headers)
        return session

    elif response.status_code == HTTPStatus.UNAUTHORIZED:
        raise CTRInvalidCredentialsError()
    elif response.status_code == HTTPStatus.NOT_FOUND:
        raise CTRInvalidJWTError()
    raise CTRUnexpectedResponseError(response.json())


def call_api(session, url, method='GET', headers=None, data=None):
    if not session.headers.get('Authorization'):
        session = set_headers(session)

    methods = {
        'GET': session.get,
        'POST': session.post
    }

    response = methods[method](url, data=data, headers=headers)
    if not response.ok:
        if response.status_code == HTTPStatus.UNAUTHORIZED:
            session = set_headers(session)
            call_api(session, url, method, headers, data)
        elif response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            raise CTRTooManyRequestsError
        elif response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR:
            raise CTRInternalServerError
        else:
            return None

    return response.json()
