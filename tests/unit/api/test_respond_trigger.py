from unittest import mock
from pytest import fixture
from http import HTTPStatus

from .utils import headers
from tests.unit.mock_for_tests import RAW_RESPONSE_TRIGGER_OBSERVABLE


def routes():
    yield '/respond/trigger'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def invalid_json():
    return [{'type': 'unknown', 'value': ''}]


def test_respond_trigger_wrong_key(route, client, valid_jwt):

    invalid_json = {
        'wrong_key': 'defender-submit-indicator-alert',
        'observable_type': 'domain',
        'observable_value': 'asdf.com'
    }

    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=invalid_json
                           )

    expected_payload = {
        'errors': [
            {
                'code': 'invalid payload',
                'message': mock.ANY,
                'type': 'fatal'
            }
        ]
    }

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def test_respond_trigger_unsupported_type_json(route, client, valid_jwt):

    invalid_json = {
        'action-id': 'defender-submit-indicator-alert',
        'observable_type': 'unknown',
        'observable_value': 'asdf.com'
    }

    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=invalid_json
                           )

    expected_payload = {
        'errors': [
            {
                'code': 'invalid payload',
                'message': mock.ANY,
                'type': 'fatal'
            }
        ]
    }

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def test_respond_trigger_unsupported_action_id(route, client, valid_jwt):

    invalid_json = {
        'action-id': 'defender-unsupported-action-id',
        'observable_type': 'domain',
        'observable_value': 'asdf.com'
    }

    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=invalid_json
                           )

    expected_payload = {
        'data': {
            'status': 'failure'
        },
        'errors': [
            {
                'code': 'invalid request',
                'message': 'Invalid request to Microsoft Defender ATP. '
                           'Unsupported action.',
                'type': 'fatal'
            }
        ]
    }

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


@mock.patch('requests.Session')
def test_respond_trigger_api_return_400(api_response, route, client, valid_jwt):

    class Session:
        headers = {'Authorization': 'ABC'}

        def post(self, *args, **kwargs):
            mock_response = mock.MagicMock()
            mock_response.ok = False
            mock_response.status_code = HTTPStatus.BAD_REQUEST
            return mock_response

        def get(self, *args, **kwargs):
            pass

        @staticmethod
        def close():
            pass

    api_response.return_value = Session

    valid_json = {
        'action-id': 'defender-submit-indicator-alert',
        'observable_type': 'domain',
        'observable_value': 'asdf.com'
    }

    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=valid_json
                           )

    expected_payload = {
        'data': {
            'status': 'failure'
        },
        'errors': [
            {
                'code': 'invalid request',
                'message': 'Invalid request to Microsoft Defender ATP.',
                'type': 'fatal'
            }
        ]
    }

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


@mock.patch('api.client.Client.call_api')
def test_respond_trigger_success(call_api, route, client, valid_jwt):

    valid_json = {
        'action-id': 'defender-submit-indicator-alert',
        'observable_type': 'domain',
        'observable_value': 'asdf.com'
    }

    call_api.side_effect = [
        (RAW_RESPONSE_TRIGGER_OBSERVABLE, None), ]

    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=valid_json
                           )

    expected_payload = {
        'data': {
            'status': 'success'
        }
    }

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload
