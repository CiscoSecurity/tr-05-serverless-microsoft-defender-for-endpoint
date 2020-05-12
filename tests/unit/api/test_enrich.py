from http import HTTPStatus

from pytest import fixture
from unittest import mock

from .utils import headers
from tests.unit.mock_for_tests import (
    EXPECTED_RESPONSE_INVALID_CREDENTIALS_ERROR,
    EXPECTED_RESPONSE_404_ERROR,
    EXPECTED_RESPONSE_500_ERROR,
    RAW_RESPONSE_MOCK,
    EXPECTED_RESPONSE
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


@mock.patch('api.enrich.call_api')
def test_enrich_call_success(call_api, route, client, valid_jwt,
                             valid_json):

    call_api.return_value = RAW_RESPONSE_MOCK

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK

    data = response.get_json()

    if route == '/observe/observables':

        sightings = data['data']['sightings']
        assert sightings['count'] == 1
        assert len(sightings['docs']) == 1
        sighting = sightings['docs'][0]
        exp_sighting = EXPECTED_RESPONSE['data']['sightings']['docs'][0]
        assert sighting.keys() == exp_sighting.keys()


@mock.patch('requests.Session.get')
def test_enrich_call_invalid_auth_error(get_token, route, client,
                                        valid_jwt, valid_json):

    res = mock.MagicMock()
    res.ok = False
    res.status_code = HTTPStatus.BAD_REQUEST
    res.json = lambda: {'error': 'unauthorized_client'}
    get_token.return_value = res

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_INVALID_CREDENTIALS_ERROR


@mock.patch('api.utils.set_headers')
def test_enrich_call_404_error(set_headers, route, client,
                               valid_jwt, valid_json):
    class Session:
        def get(self):
            mock_response = mock.MagicMock()
            mock_response.ok = False
            mock_response.status_code = HTTPStatus.NOT_FOUND
            return mock_response

    set_headers.return_value = Session

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_404_ERROR


@mock.patch('api.utils.set_headers')
def test_enrich_call_500_error(set_headers, route, client,
                               valid_jwt, valid_json):

    class Session:
        def get(self):
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


@mock.patch('api.utils.set_headers')
def test_enrich_call_400_error(set_headers, route, client,
                               valid_jwt, valid_json):

    class Session:
        def get(self):
            mock_response = mock.MagicMock()
            mock_response.ok = False
            mock_response.status_code = HTTPStatus.BAD_REQUEST
            mock_response.json = lambda: {
                'error': {'message': 'a bad request error.'}
            }
            return mock_response

    set_headers.return_value = Session

    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK

    message = response.get_json()['errors'][0]['message']
    assert message == 'a bad request error.'
