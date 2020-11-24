from http import HTTPStatus

from pytest import fixture
from unittest import mock

from .utils import headers


def routes():
    yield '/refer/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def invalid_json():
    return [{'type': 'unknown', 'value': ''}]


@fixture(scope='module')
def valid_json():
    return [
        {'type': 'sha1',
         'value': '0d549631690ea297c25b2a4e133cacb8a87b97c6'},
        {'type': 'domain',
         'value': 'asdf.com'},
        {'type': 'ip',
         'value': '1.1.1.1'},
    ]


def test_refer_observables_empty_observables(route, client, valid_jwt):

    empty_json = []

    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=empty_json
                           )

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == {'data': []}


def test_refer_observables_unsupported_observables(route, client, valid_jwt,
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


def test_refer_observables_success(route, client, valid_jwt, valid_json):

    exp_response = {
        "data": [
            {
                "categories": [
                    "Search",
                    "Microsoft Defender for Endpoint"
                ],
                "description":
                    "Lookup this SHA1 on Microsoft Defender for Endpoint",
                "id": "ref-md-search-"
                      "sha1-0d549631690ea297c25b2a4e133cacb8a87b97c6",
                "title": "Search for this SHA1",
                "url": "https://securitycenter.windows.com"
                       "/files/0d549631690ea297c25b2a4e133cacb8a87b97c6"
            },
            {
                "categories": [
                    "Search",
                    "Microsoft Defender for Endpoint"
                ],
                "description":
                    "Lookup this Domain on Microsoft Defender for Endpoint",
                "id": "ref-md-search-domain-asdf.com",
                "title": "Search for this Domain",
                "url": "https://securitycenter.windows.com/urls/asdf.com"
            },
            {
                "categories": [
                    "Search",
                    "Microsoft Defender for Endpoint"
                ],
                "description":
                    "Lookup this IP on Microsoft Defender for Endpoint",
                "id": "ref-md-search-ip-1.1.1.1",
                "title": "Search for this IP",
                "url": "https://securitycenter.windows.com/ips/1.1.1.1"
            }
        ]
    }

    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=valid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == exp_response
