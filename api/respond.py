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
        params = "$filter=indicatorValue+eq+'{value}'&$top=1".format(
            value=observable['value']).encode('utf-8')

        credentials = get_jwt()
        client = Client(credentials)
        client.open_session()
        response, error = client.call_api(current_app.config['INDICATOR_URL'],
                                          params=params)

        query_params = {'observable_type': observable['type'],
                        'observable_value': observable['value']}

        if response and response.get('value'):
            obj = response['value'][0]
            human_action = 'Alert and Block' \
                if obj['action'] == 'AlertAndBlock' else obj['action']
            query_params['indicator_id'] = obj['id']
            actions = [
                {
                    'id': 'defender-remove-indicator',
                    'title': 'Remove indicator: {action} - {title}'.format(
                        action=human_action,
                        title=obj['title']
                    ),
                    'description': f'Remove indicator with {human_action} '
                                   f'action for {observable["value"]}',
                    'categories': [
                        'Defender ATP',
                        'Remove Indicator'
                    ],
                    'query-params': query_params
                },
            ]

        else:
            actions = [
                {
                    'id': 'defender-add-indicator-alert',
                    'title': 'Add indicator: Alert',
                    'description': f'Add indicator with Alert action '
                                   f'for {observable["value"]}',
                    'categories': [
                        'Defender ATP',
                        'Add Indicator'
                    ],
                    'query-params': query_params
                },
                {
                    'id': 'defender-add-indicator-alert-and-block',
                    'title': 'Add indicator: Alert and Block',
                    'description': f'Add indicator with Alert and Block action'
                                   f' for {observable["value"]}',
                    'categories': [
                        'Defender ATP',
                        'Add Indicator'
                    ],
                    'query-params': query_params
                },
                {
                    'id': 'defender-add-indicator-allowed',
                    'title': 'Add indicator: Allowed',
                    'description': f'Add indicator with Allowed action '
                                   f'for {observable["value"]}',
                    'categories': [
                        'Defender ATP',
                        'Add Indicator'
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
        'defender-add-indicator-alert': {
            'url': current_app.config['INDICATOR_URL'],
            'method': 'POST',
            'data': {
                'indicatorValue': data['observable_value'],
                'indicatorType': mapping_by_type[data['observable_type']],
                'action': 'Alert',
                'title': title,
                'description': description,
                'severity': 'High'
            }
        },
        'defender-add-indicator-alert-and-block': {
            'url': current_app.config['INDICATOR_URL'],
            'method': 'POST',
            'data': {
                'indicatorValue': data['observable_value'],
                'indicatorType': mapping_by_type[data['observable_type']],
                'action': 'AlertAndBlock',
                'title': title,
                'description': description,
                'severity': 'High'
            }
        },
        'defender-add-indicator-allowed': {
            'url': current_app.config['INDICATOR_URL'],
            'method': 'POST',
            'data': {
                'indicatorValue': data['observable_value'],
                'indicatorType': mapping_by_type[data['observable_type']],
                'action': 'Allowed',
                'title': title,
                'description': description
            }
        },
        'defender-remove-indicator': {
            'url': current_app.config['INDICATOR_URL'] + '/' + str(
                data.get('indicator_id', '')),
            'method': 'DELETE',
            'data': {}
        }
    }

    result = {'data': {'status': 'success'}}

    item = actions.get(data['action-id'])
    if not item:
        result['data']['status'] = 'failure'
        result['errors'] = [CTRBadRequestError("Unsupported action.").json, ]
        return jsonify(result)

    if item['data']:
        action = json.dumps(item['data']).encode('utf-8')
    else:
        action = None
    credentials = get_jwt()
    client = Client(credentials)
    client.open_session()
    response, error = client.call_api(item['url'], item['method'], data=action)
    client.close_session()

    if error is not None:
        result['data']['status'] = 'failure'
        result['errors'] = [CTRBadRequestError(error).json, ]

    return jsonify(result)
