import json
from urllib.parse import urlparse

from authlib.jose import jwt
from authlib.jose.errors import BadSignatureError, DecodeError

from flask import request, current_app, jsonify, g

from api.errors import AuthorizationError


def get_auth_token():
    """
    Parse the incoming request's Authorization Bearer JWT for some credentials.
    """
    expected_errors = {
        KeyError: 'Authorization header is missing',
        AssertionError: 'Wrong authorization type'
    }

    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_jwt():
    """
    Get Authorization token
    and validate its signature against the application's secret key.
    """
    expected_errors = {
        KeyError: 'Wrong JWT payload structure',
        TypeError: '<SECRET_KEY> is missing',
        BadSignatureError: 'Failed to decode JWT with provided key',
        DecodeError: 'Wrong JWT structure'
    }

    token = get_auth_token()

    try:
        credentials = jwt.decode(token, current_app.config['SECRET_KEY'])
        client_id = credentials['client_id']
        client_secret = credentials['client_secret']
        tenant_id = credentials['tenant_id']
        return {'client_id': client_id,
                'client_secret': client_secret,
                'tenant_id': tenant_id}
    except tuple(expected_errors) as error:
        message = expected_errors[error.__class__]
        raise AuthorizationError(message)


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


def format_docs(docs):
    return {'count': len(docs), 'docs': docs}


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
        data['data'] = {'sightings': format_docs(g.sightings)}

    return jsonify(data)


def group_observables(relay_input):
    # Leave only unique observables

    result = []
    for observable in relay_input:
        o_value = observable['value']
        o_type = observable['type'].lower()

        # Get only supported types.
        if o_type in current_app.config['MD_ATP_OBSERVABLE_TYPES'].keys():
            obj = {'type': o_type, 'value': o_value}
            if obj in result:
                continue
            result.append(obj)

    return result


def is_url(value):
    try:
        result = urlparse(value)
        return all((result.scheme, result.netloc))
    except ValueError:
        return False
