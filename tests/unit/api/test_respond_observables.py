from unittest import mock
from pytest import fixture
from http import HTTPStatus

from .utils import headers
from tests.unit.mock_for_tests import (
    EXPECTED_RESPONSE_RESPOND_OBSERVABLE,
    EXPECTED_RESPONSE_RESPOND_TARGET,
    AVAILABLE_MACHINE_ACTIONS_RESPONSE,
    HISTORY_MACHINE_ACTIONS_RESPONSE_EMPTY,
    HISTORY_MACHINE_ACTIONS_RESPONSE_ISOLATE,
    HISTORY_MACHINE_ACTIONS_RESPONSE_RESTRICT_CODE_EXECUTION
)


def routes():
    yield '/respond/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def invalid_json():
    return [{'type': 'unknown', 'value': ''}]


def test_respond_observables_empty_observables(route, client, valid_jwt):

    empty_json = []

    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=empty_json
                           )

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == {'data': []}


def test_respond_observables_unsupported_observables(route, client, valid_jwt,
                                                     invalid_json):

    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=invalid_json
                           )

    expected_payload = {
        'errors': [
            {
                'code': 'invalid payload',
                'message': mock.ANY,
                'type': 'fatal',
            }
        ]
    }

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


@mock.patch('api.client.Client.call_api')
def test_respond_observables_success(call_api, route, client, valid_jwt):

    valid_json = [{'type': 'domain', 'value': 'asdf.com'}]

    call_api.return_value = (
        {
            '@odata.context': 'https://api.securitycenter.windows.com'
                              '/api/v1.0/$metadata#Indicators',
            'value': []},
        None
    )

    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=valid_json
                           )

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_RESPOND_OBSERVABLE


@mock.patch('api.client.Client.call_api')
def test_respond_target_success(call_api, route, client, valid_jwt):
    valid_json = [{'type': 'device',
                   'value': 'ebfef0ac4aa2ab0b4342c9cd078a6dfb6c66adc0'}]

    call_api.side_effect = (
        (AVAILABLE_MACHINE_ACTIONS_RESPONSE, None),
        (HISTORY_MACHINE_ACTIONS_RESPONSE_EMPTY, None),
        (HISTORY_MACHINE_ACTIONS_RESPONSE_EMPTY, None)
    )

    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=valid_json)

    assert response.status_code == HTTPStatus.OK

    exp = sorted(EXPECTED_RESPONSE_RESPOND_TARGET['data'],
                 key=lambda x: x['id'])
    current = sorted(response.get_json()['data'], key=lambda x: x['id'])

    assert current == exp


@mock.patch('api.client.Client.call_api')
def test_respond_target_unisolate(call_api, route, client, valid_jwt):
    valid_json = [{'type': 'device',
                   'value': 'ebfef0ac4aa2ab0b4342c9cd078a6dfb6c66adc0'}]

    call_api.side_effect = (
        (AVAILABLE_MACHINE_ACTIONS_RESPONSE, None),
        (HISTORY_MACHINE_ACTIONS_RESPONSE_ISOLATE, None),
        (HISTORY_MACHINE_ACTIONS_RESPONSE_EMPTY, None)
    )

    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=valid_json)

    exp = {
        'categories': ['Microsoft Defender ATP', 'Machine Actions'],
        'description': 'Release device from isolation',
        'id': 'microsoft-defender-atp-Unisolate',
        'query-params': {
            'observable_type': 'device',
            'observable_value': 'ebfef0ac4aa2ab0b4342c9cd078a6dfb6c66adc0'
        },
        'title': 'Release device from isolation'
    }

    assert response.status_code == HTTPStatus.OK
    assert exp in response.get_json()['data']


@mock.patch('api.client.Client.call_api')
def test_respond_target_unrestrict_code_execution(call_api, route,
                                                  client, valid_jwt):
    valid_json = [{'type': 'device',
                   'value': 'ebfef0ac4aa2ab0b4342c9cd078a6dfb6c66adc0'}]

    call_api.side_effect = (
        (AVAILABLE_MACHINE_ACTIONS_RESPONSE, None),
        (HISTORY_MACHINE_ACTIONS_RESPONSE_EMPTY, None),
        (HISTORY_MACHINE_ACTIONS_RESPONSE_RESTRICT_CODE_EXECUTION, None)
    )

    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=valid_json)

    exp = {
        'categories': ['Microsoft Defender ATP', 'Machine Actions'],
        'description': 'Remove app restriction',
        'id': 'microsoft-defender-atp-UnrestrictCodeExecution',
        'query-params': {
            'observable_type': 'device',
            'observable_value': 'ebfef0ac4aa2ab0b4342c9cd078a6dfb6c66adc0'
        },
        'title': 'Remove app restriction'
    }

    assert response.status_code == HTTPStatus.OK
    assert exp in response.get_json()['data']


@mock.patch('api.client.Client.call_api')
def test_respond_target_failure(call_api, route, client, valid_jwt):
    valid_json = [{'type': 'device',
                   'value': 'ebfef0ac4aa2ab0b4342c9cd078a6dfb6c66adc0'}]

    call_api.side_effect = (
        (None, 'Any error, but not 401, 429, 500'),
        (HISTORY_MACHINE_ACTIONS_RESPONSE_EMPTY, None),
        (HISTORY_MACHINE_ACTIONS_RESPONSE_EMPTY, None)
    )

    expected_payload = {
        'errors': [
            {
                'code': 'invalid request',
                'message': 'Invalid request to Microsoft Defender ATP.',
                'type': 'fatal',
            }
        ]
    }

    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=valid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload

    call_api.side_effect = (
        (AVAILABLE_MACHINE_ACTIONS_RESPONSE, None),
        (None, 'Any error, but not 401, 429, 500'),
        (HISTORY_MACHINE_ACTIONS_RESPONSE_EMPTY, None)
    )

    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=valid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload

    call_api.side_effect = (
        (AVAILABLE_MACHINE_ACTIONS_RESPONSE, None),
        (HISTORY_MACHINE_ACTIONS_RESPONSE_EMPTY, None),
        (None, 'Any error, but not 401, 429, 500')
    )

    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=valid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload
