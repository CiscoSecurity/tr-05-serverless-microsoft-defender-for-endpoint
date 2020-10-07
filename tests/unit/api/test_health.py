from http import HTTPStatus

from pytest import fixture
from unittest import mock

from .utils import headers
from tests.unit.mock_for_tests import (EXPECTED_RESPONSE_BAD_SIGNATURE,
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


def test_health_call_success(route, client, valid_jwt):
    response = client.post(route, headers=headers(valid_jwt))
    assert response.status_code == HTTPStatus.OK
