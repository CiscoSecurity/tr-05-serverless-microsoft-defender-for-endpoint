from http import HTTPStatus

from pytest import fixture
from unittest import mock

from .utils import headers
from tests.unit.mock_for_tests import (EXPECTED_RESPONSE_BAD_SIGNATURE,
                                       EXPECTED_RESPONSE_MISS_AUTH_ERROR,
                                       EXPECTED_RESPONSE_WRONG_AUTH_TYPE_ERROR,
                                       EXPECTED_RESPONSE_400_ERROR)


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_with_invalid_jwt_failure(route, client, invalid_jwt):
    response = client.post(route, headers=headers(invalid_jwt))
    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_BAD_SIGNATURE


@mock.patch('requests.Session.get')
def test_health_call_with_without_token_failure(session, route,
                                                client, valid_jwt):
    res = mock.MagicMock()
    res.ok = True
    res.status_code = HTTPStatus.OK
    res.json = lambda: {'without_token': 'skip', 'token_type': 'Bearer'}
    session.return_value = res

    response = client.post(route, headers=headers(valid_jwt))
    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_400_ERROR


@mock.patch('requests.Session')
def test_health_call_auth_unexpect_error(session, route, client, valid_jwt):
    class Session:
        headers = {}

        def get(self, *args, **kwargs):
            res = mock.MagicMock()
            res.ok = False
            res.status_code = HTTPStatus.FORBIDDEN
            return res

    session.return_value = Session

    expected_payload = {
        'errors': [
            {
                'code': 'unknown',
                'message': mock.ANY,
                'type': 'fatal',
            }
        ]
    }

    response = client.post(route, headers=headers(valid_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


@mock.patch('api.client.Client.call_api')
def test_health_call_success(call_api, route, client, valid_jwt):
    call_api.return_value = {
        "@odata.context": "https://api-us.securitycenter.windows.com"
                          "/api/$metadata#ExposureScore/$entity",
        "time": "2019-12-03T07:23:53.280499Z",
        "score": 33.491554051195706
    }

    response = client.post(route, headers=headers(valid_jwt))
    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == {'data': {'status': 'ok'}}


def test_jwt_miss_auth_header(route, client):
    response = client.post(route, headers={'Not_Authorization': {}})
    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_MISS_AUTH_ERROR


def test_jwt_wrong_auth_type(route, client, valid_jwt):
    response = client.post(
        route,
        headers={'Authorization': f'Not_Bearer {valid_jwt}'}
    )
    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_WRONG_AUTH_TYPE_ERROR
