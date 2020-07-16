from unittest import mock
from pytest import fixture
from http import HTTPStatus

from .utils import headers
from tests.unit.mock_for_tests import EXPECTED_RESPONSE_RESPOND_OBSERVABLE


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


def test_respond_observables_success(route, client, valid_jwt):

    valid_json = [{'type': 'domain', 'value': 'asdf.com'}]

    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=valid_json
                           )

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_RESPONSE_RESPOND_OBSERVABLE
