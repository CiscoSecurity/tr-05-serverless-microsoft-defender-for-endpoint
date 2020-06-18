from http import HTTPStatus

from pytest import fixture
from unittest import mock

from .utils import headers
from tests.unit.mock_for_tests import (
    EXPECTED_RESPONSE_INVALID_CREDENTIALS_ERROR,
    EXPECTED_RESPONSE_500_ERROR,
    EXPECTED_RESPONSE_429_ERROR,
    RAW_RESPONSE_MOCK,
    EXPECTED_RESPONSE,
    AH_RESPONSE,
    GET_SHA256_FOR_0d549631690ea297c25b2a4e133cacb8a87b97c6,
    GET_SHA256_FOR_ecb05717e416d965255387f4edc196889aa12c67
)


def routes():
    yield '/observe/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def invalid_json():
    return [{'type': 'unknown', 'value': ''}]


def test_enrich_call_with_invalid_json_failure(route, client, valid_jwt,
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


@fixture(scope='module')
def valid_json():
    return [
        {
            'type': 'sha1',
            'value': '36c5d12033b2eaf251bae61c00690ffb17fddc87'
        },
    ]


@mock.patch('api.client.Client.call_api')
def test_enrich_call_success(call_api, route, client, valid_jwt,
                             valid_json):

    for_target_response = {
        'osPlatform': 'Windows10',
        'lastIpAddress': '172.17.230.209'
    }

    exp_target_observables = [
        {'type': 'hostname', 'value': 'desktop-au3ip5k'},
        {'type': 'ip', 'value': '172.17.230.209'},
        {'type': 'user', 'value': 'Serhii'}
    ]

    call_api.side_effect = [
        RAW_RESPONSE_MOCK, AH_RESPONSE,
        for_target_response,
        GET_SHA256_FOR_0d549631690ea297c25b2a4e133cacb8a87b97c6,
        GET_SHA256_FOR_ecb05717e416d965255387f4edc196889aa12c67,
        for_target_response]

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK

    data = response.get_json()

    if route == '/observe/observables':

        sightings = data['data']['sightings']
        assert sightings['count'] == 2
        assert len(sightings['docs']) == 2
        sighting = sightings['docs'][0]
        exp_sighting = EXPECTED_RESPONSE['data']['sightings']['docs'][0]
        assert sighting.keys() == exp_sighting.keys()
        assert exp_target_observables == sighting['targets'][0]['observables']


@mock.patch('requests.Session.get')
def test_enrich_call_invalid_auth_401_error(get_token, route, client,
                                            valid_jwt, valid_json):

    res = mock.MagicMock()
    res.ok = False
    res.status_code = HTTPStatus.UNAUTHORIZED
    get_token.return_value = res

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_INVALID_CREDENTIALS_ERROR


@mock.patch('requests.Session.get')
def test_enrich_call_invalid_auth_400_error(get_token, route, client,
                                            valid_jwt, valid_json):

    res = mock.MagicMock()
    res.ok = False
    res.status_code = HTTPStatus.BAD_REQUEST
    get_token.return_value = res

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_INVALID_CREDENTIALS_ERROR


@mock.patch('requests.Session')
def test_enrich_call_500_error(set_headers, route, client,
                               valid_jwt, valid_json):

    class Session:
        headers = {'Authorization': 'ABC'}

        def post(self, *args, **kwargs):
            pass

        def get(self, *args, **kwargs):
            mock_response = mock.MagicMock()
            mock_response.ok = False
            mock_response.status_code = HTTPStatus.INTERNAL_SERVER_ERROR
            return mock_response

    set_headers.return_value = Session

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_500_ERROR


@mock.patch('requests.Session')
def test_enrich_call_429_error(set_headers, route, client,
                               valid_jwt, valid_json):

    class Session:
        headers = {'Authorization': 'ABC'}

        def post(self, *args, **kwargs):
            pass

        def get(self, *args, **kwargs):
            mock_response = mock.MagicMock()
            mock_response.ok = False
            mock_response.status_code = HTTPStatus.TOO_MANY_REQUESTS
            return mock_response

    set_headers.return_value = Session

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_429_ERROR


@mock.patch('requests.Session')
def test_enrich_call_wrong_observable(set_headers, route, client,
                                      valid_jwt):

    wrong_ip_json = [
        {
            'type': 'ip',
            'value': '@#$%^&'
        },
    ]

    class Session:
        headers = {'Authorization': 'ABC'}

        def post(self, *args, **kwargs):
            mock_response = mock.MagicMock()
            mock_response.json.return_value = {'Results': []}
            return mock_response

        def get(self, *args, **kwargs):
            mock_response = mock.MagicMock()
            mock_response.ok = False
            mock_response.status_code = HTTPStatus.NOT_FOUND
            return mock_response

        @staticmethod
        def close():
            pass

    set_headers.return_value = Session

    response = client.post(
        route, headers=headers(valid_jwt), json=wrong_ip_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == {'data': {}}
