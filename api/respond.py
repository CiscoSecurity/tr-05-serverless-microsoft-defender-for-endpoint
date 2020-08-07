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


TR_SUPPORTED_ACTIONS = {
    'FullIsolation': 'Full isolation',
    'SelectiveIsolation': 'Selective isolation',
    'RunQuickAntiVirusScan': 'Run quick antivirus scan',
    'RunFullAntiVirusScan': 'Run full antivirus scan',
    'CollectInvestigationPackage': 'Collect investigation package',
    'RestrictCodeExecution': 'Restrict app execution',
    'InitiateInvestigation': 'Initiate automated investigation'
}


TR_REVERSE_ACTIONS = {
    'Unisolate': 'Release device from isolation',
    'UnrestrictCodeExecution': 'Remove app restriction'
}


def get_supported_actions(client, machine_id):
    url = f"{current_app.config['BASE_URL']}" \
          f"/machines/{machine_id}/availableMachineActions"

    response, error = client.call_api(url)
    if error:
        raise CTRBadRequestError()
    md_supported_actions = set()
    for item in response.get('value', []):
        if item['isAvailable']:
            if item['action'] == 'RunAntiVirusScan':
                md_supported_actions.add('RunQuickAntiVirusScan')
                md_supported_actions.add('RunFullAntiVirusScan')
            else:
                md_supported_actions.add(item['action'])

    actions = md_supported_actions.intersection(
        set(TR_SUPPORTED_ACTIONS.keys())
    )
    return actions


def get_dynamic_actions(client, machine_id, actions):
    url = f"{current_app.config['BASE_URL']}" \
          f"/machines/{machine_id}/machineactions?"

    filter_by_isolate = "$filter=type in ('Unisolate', 'Isolate') " \
                        "and status eq 'Succeeded'&$top=1"

    filter_by_restrict = "$filter=type in (" \
                         "'UnrestrictCodeExecution', " \
                         "'RestrictCodeExecution'" \
                         ") and status eq 'Succeeded'&$top=1"

    if 'FullIsolation' in actions or 'SelectiveIsolation' in actions:
        response, error = client.call_api(url + filter_by_isolate)
        if error:
            raise CTRBadRequestError()
        if response.get('value', []) and \
                response['value'][0]['type'] == 'Isolate':
            actions.discard('FullIsolation')
            actions.discard('SelectiveIsolation')
            actions.add('Unisolate')

    if 'RestrictCodeExecution' in actions:
        response, error = client.call_api(url + filter_by_restrict)
        if error:
            raise CTRBadRequestError()
        if response.get('value', []) and \
                response['value'][0]['type'] == 'RestrictCodeExecution':
            actions.discard('RestrictCodeExecution')
            actions.add('UnrestrictCodeExecution')
    return actions


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

        if observable['type'] == 'device':
            credentials = get_jwt()
            client = Client(credentials)
            client.open_session()

            _actions = get_supported_actions(client, observable['value'])
            _actions = get_dynamic_actions(client, observable['value'], _actions)

            actions = []
            for item in _actions:
                action = {}
                action['id'] = f'microsoft-defender-atp-{item}'

                action_title = \
                    TR_SUPPORTED_ACTIONS.get(item) or TR_REVERSE_ACTIONS[item]

                action['title'] = action_title
                action['description'] = action_title

                action['categories'] = [
                    'Microsoft Defender ATP',
                    'Machine Actions'
                ]
                action['query-params'] = query_params

                actions.append(action)

            client.close_session()

        else:
            actions = [
                {
                    'id': 'microsoft-defender-atp-submit-indicator-alert',
                    'title': 'Submit indicator with Alert',
                    'description': f'Submit indicator with alert action '
                                   f'for {observable["type"].upper()}',
                    'categories': [
                        'Microsoft Defender ATP',
                        'Submit Indicator'
                    ],
                    'query-params': query_params
                },
                {
                    'id': 'microsoft-defender-atp-submit-indicator-alert-and-block',
                    'title': 'Submit indicator with Alert and Block',
                    'description': f'Submit indicator with Alert and Block action '
                                   f'for {observable["type"].upper()}',
                    'categories': [
                        'Microsoft Defender ATP',
                        'Submit Indicator'
                    ],
                    'query-params': query_params
                },
                {
                    'id': 'microsoft-defender-atp-submit-indicator-allowed',
                    'title': 'Submit indicator with Allowed',
                    'description': f'Submit indicator with Allowed action '
                                   f'for {observable["type"].upper()}',
                    'categories': [
                        'Microsoft Defender ATP',
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

    if data['observable_type'] == 'device':
        comment = 'Performed via SecureX Threat Response'
        actions = {
            'microsoft-defender-atp-FullIsolation': {
                'url': '{base_url}/machines/{machine_id}/isolate'.format(
                    base_url=current_app.config['BASE_URL'],
                    machine_id=data['observable_value']),
                'data': {
                    'Comment': comment,
                    'IsolationType': 'Full'
                }
            },
            'microsoft-defender-atp-SelectiveIsolation': {
                'url': '{base_url}/machines/{machine_id}/isolate'.format(
                    base_url=current_app.config['BASE_URL'],
                    machine_id=data['observable_value']),
                'data': {
                    'Comment': comment,
                    'IsolationType': 'Selective'
                }
            },
            'microsoft-defender-atp-Unisolate': {
                'url': '{base_url}/machines/{machine_id}/unisolate'.format(
                    base_url=current_app.config['BASE_URL'],
                    machine_id=data['observable_value']),
                'data': {
                    'Comment': comment
                }
            },
            'microsoft-defender-atp-RestrictCodeExecution': {
                'url': '{base_url}/machines/{machine_id}'
                       '/restrictCodeExecution'.format(
                    base_url=current_app.config['BASE_URL'],
                    machine_id=data['observable_value']),
                'data': {
                    'Comment': comment
                }
            },
            'microsoft-defender-atp-UnrestrictCodeExecution': {
                'url': '{base_url}/machines/{machine_id}'
                       '/unrestrictCodeExecution'.format(
                    base_url=current_app.config['BASE_URL'],
                    machine_id=data['observable_value']),
                'data': {
                    'Comment': comment
                }
            },
            'microsoft-defender-atp-RunQuickAntiVirusScan': {
                'url': '{base_url}/machines/{machine_id}'
                       '/runAntiVirusScan'.format(
                    base_url=current_app.config['BASE_URL'],
                    machine_id=data['observable_value']),
                'data': {
                    'Comment': comment,
                    'ScanType': 'Quick'
                }
            },
            'microsoft-defender-atp-RunFullAntiVirusScan': {
                'url': '{base_url}/machines/{machine_id}'
                       '/runAntiVirusScan'.format(
                    base_url=current_app.config['BASE_URL'],
                    machine_id=data['observable_value']),
                'data': {
                    'Comment': comment,
                    'ScanType': 'Full'
                }
            },
            'microsoft-defender-atp-CollectInvestigationPackage': {
                'url': '{base_url}/machines/{machine_id}'
                       '/collectInvestigationPackage'.format(
                    base_url=current_app.config['BASE_URL'],
                    machine_id=data['observable_value']),
                'data': {
                    'Comment': comment
                }
            },
            'microsoft-defender-atp-InitiateInvestigation': {
                'url': '{base_url}/machines/{machine_id}'
                       '/startInvestigation'.format(
                    base_url=current_app.config['BASE_URL'],
                    machine_id=data['observable_value']),
                'data': {
                    'Comment': comment
                }
            }
        }

    else:
        actions = {
            'microsoft-defender-atp-submit-indicator-alert': {
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
            'microsoft-defender-atp-submit-indicator-alert-and-block': {
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
            'microsoft-defender-atp-submit-indicator-allowed': {
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
