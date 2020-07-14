import json
from functools import partial

from flask import Blueprint, current_app, g, jsonify

from api.schemas import ObservableSchema, ActionFormParamsSchema
from api.utils import (get_json, jsonify_data, jsonify_errors, get_jwt,
                       group_observables)
from api.client import Client
from api.errors import CTRBadRequestError

respond_api = Blueprint('respond', __name__)


get_observables = partial(get_json, schema=ObservableSchema(many=True))
get_action_form_params = partial(get_json, schema=ActionFormParamsSchema())


@respond_api.route('/respond/observables', methods=['POST'])
def respond_observables():
    observables, error = get_observables()
    if error:
        return jsonify_errors(error)

    observables = group_observables(observables)

    if not observables:
        return jsonify_data([])

    g.actions = []
    for observable in observables:
        query_params = {'observable_type': observable['type'],
                        'observable_value': observable['value']}
        actions = [
            {
                'id': 'defender-submit-indicator-alert',
                'title': 'Submit indicator with Alert',
                'description': f'Submit indicator with alert action '
                               f'for {observable["type"].upper()}',
                'categories': [
                    'Defender ATP',
                    'Submit Indicator'
                ],
                'query-params': query_params
            },
            {
                'id': 'defender-submit-indicator-alert-and-block',
                'title': 'Submit indicator with Alert and Block',
                'description': f'Submit indicator with Alert and Block action '
                               f'for {observable["type"].upper()}',
                'categories': [
                    'Defender ATP',
                    'Submit Indicator'
                ],
                'query-params': query_params
            },
            {
                'id': 'defender-submit-indicator-allowed',
                'title': 'Submit indicator with Allowed',
                'description': f'Submit indicator with Allowed action '
                               f'for {observable["type"].upper()}',
                'categories': [
                    'Defender ATP',
                    'Submit Indicator'
                ],
                'query-params': query_params
            }
        ]
        g.actions.extend(actions)
    return jsonify_data(g.actions)


@respond_api.route('/respond/trigger', methods=['POST'])
def respond_trigger():
    mapping_by_type = {
        'sha1': 'FileSha1',
        'sha256': 'FileSha256',
        'ip': 'IpAddress',
        'ipv6': 'IpAddress',
        'domain': 'DomainName'
    }
    data, error = get_action_form_params()

    if error:
        return jsonify_errors(error)

    title = 'From SecureX Threat Response'
    description = 'This indicator was added via SecureX Threat Response ' \
                  'by the UI or API response actions'

    actions = {
        'defender-submit-indicator-alert': {
            'url': current_app.config['SUBMIT_INDICATOR_URL'],
            'data': {
                'indicatorValue': data['observable_value'],
                'indicatorType': mapping_by_type[data['observable_type']],
                'action': 'Alert',
                'title': title,
                'description': description,
                'severity': 'High'
            }
        },
        'defender-submit-indicator-alert-and-block': {
            'url': current_app.config['SUBMIT_INDICATOR_URL'],
            'data': {
                'indicatorValue': data['observable_value'],
                'indicatorType': mapping_by_type[data['observable_type']],
                'action': 'AlertAndBlock',
                'title': title,
                'description': description,
                'severity': 'High'
            }
        },
        'defender-submit-indicator-allowed': {
            'url': current_app.config['SUBMIT_INDICATOR_URL'],
            'data': {
                'indicatorValue': data['observable_value'],
                'indicatorType': mapping_by_type[data['observable_type']],
                'action': 'Allowed',
                'title': title,
                'description': description
            }
        }
    }

    result = {'data': {'status': 'success'}}

    item = actions.get(data['action-id'])
    if not item:
        result['data']['status'] = 'failure'
        result['errors'] = [CTRBadRequestError("Unsupported action.").json, ]
        return jsonify(result)

    action = json.dumps(item['data']).encode('utf-8')
    credentials = get_jwt()
    client = Client(credentials)
    client.open_session()
    response, error = client.call_api(item['url'], 'POST', data=action)
    client.close_session()

    if error is not None:
        result['data']['status'] = 'failure'
        result['errors'] = [CTRBadRequestError().json, ]

    return jsonify(result)
